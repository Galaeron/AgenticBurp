import unittest
from unittest.mock import AsyncMock, patch

import httpx

from models import Finding, HttpExchange
from safety_gate import get_default_gate, reset_default_gate
from run_context import RunContext, ScopePolicy
from test_run_context import _Fixture
from validators.sqlmap import (
    SqlmapValidator,
    _json_top_level_params,
    _mutate_json_param,
    _form_top_level_params,
    _mutate_form_param,
    _query_top_level_params,
    _mutate_query_param,
    _responses_differ,
    _text_has_db_error_markers,
    _inferred_content_type_for_body,
    _looks_like_auth_request,
)


def _login_exchange(body='{"email":"bob@bob.com","password":"bobbob"}', url="http://localhost:3000/rest/user/login"):
    return HttpExchange(
        url=url, method="POST",
        request_headers={"Content-Type": "application/json"},
        request_body=body, response_status=200,
    )


def _finding(vulnerability_class="sqli"):
    return Finding(
        vulnerability_class=vulnerability_class, confidence=0.5, summary="s", evidence="e",
        suggested_test="t", basis="derived",
    )


class JsonParamHelpersTests(unittest.TestCase):
    def test_top_level_params_lists_string_and_numeric_fields(self):
        params = _json_top_level_params('{"email":"a@b.com","age":30,"active":true}')
        self.assertIn("email", params)
        self.assertIn("age", params)
        self.assertNotIn("active", params)  # bool excluded -- not a SQL-relevant mutation

    def test_mutate_preserves_other_fields(self):
        result = _mutate_json_param('{"email":"a@b.com","password":"x"}', "email", "' OR '1'='1' -- ")
        self.assertEqual(result, '{"email": "\' OR \'1\'=\'1\' -- ", "password": "x"}')

    def test_mutate_missing_param_returns_none(self):
        self.assertIsNone(_mutate_json_param('{"email":"a@b.com"}', "not_present", "x"))

    def test_non_dict_json_returns_no_params(self):
        self.assertEqual(_json_top_level_params('[1,2,3]'), [])


class FormParamHelpersTests(unittest.TestCase):
    def test_top_level_params(self):
        self.assertEqual(_form_top_level_params("id=1&sort=name"), ["id", "sort"])

    def test_mutate_percent_encodes_and_preserves_other_fields(self):
        result = _mutate_form_param("id=1&sort=name", "sort", "' OR '1'='1' -- ")
        self.assertIn("id=1", result)
        self.assertIn("sort=%27", result)
        self.assertNotIn("name", result)


class QueryParamHelpersTests(unittest.TestCase):
    def test_top_level_params(self):
        self.assertEqual(_query_top_level_params("https://x.test/search?q=widget&page=1"), ["q", "page"])

    def test_mutate_preserves_path_and_other_params(self):
        result = _mutate_query_param("https://x.test/search?q=widget&page=1", "q", "' OR '1'='1' -- ")
        self.assertTrue(result.startswith("https://x.test/search?"))
        self.assertIn("page=1", result)
        self.assertNotIn("widget", result)

    def test_mutate_missing_param_returns_none(self):
        self.assertIsNone(_mutate_query_param("https://x.test/search?q=widget", "not_present", "x"))


class ResponsesDifferTests(unittest.TestCase):
    def test_status_code_difference_is_always_a_differential(self):
        a = httpx.Response(200, request=httpx.Request("GET", "https://x.test"))
        b = httpx.Response(401, request=httpx.Request("GET", "https://x.test"))
        self.assertTrue(_responses_differ(a, b))

    def test_same_status_and_length_is_not_a_differential(self):
        a = httpx.Response(200, content=b"x" * 100, request=httpx.Request("GET", "https://x.test"))
        b = httpx.Response(200, content=b"y" * 100, request=httpx.Request("GET", "https://x.test"))
        self.assertFalse(_responses_differ(a, b))

    def test_large_relative_length_delta_at_same_status_is_a_differential(self):
        a = httpx.Response(200, content=b"x" * 1000, request=httpx.Request("GET", "https://x.test"))
        b = httpx.Response(200, content=b"x" * 10, request=httpx.Request("GET", "https://x.test"))
        self.assertTrue(_responses_differ(a, b))

    def test_small_absolute_delta_on_tiny_responses_is_not_flagged_as_noise(self):
        a = httpx.Response(200, content=b"ok", request=httpx.Request("GET", "https://x.test"))
        b = httpx.Response(200, content=b"okk", request=httpx.Request("GET", "https://x.test"))
        self.assertFalse(_responses_differ(a, b))


class DbErrorMarkerTests(unittest.TestCase):
    def test_sqlite_error_text_detected(self):
        self.assertTrue(_text_has_db_error_markers(
            "Error: SQLITE_ERROR: SELECTs to the left and right of UNION do not have the same number of result columns"
        ))

    def test_ordinary_response_not_flagged(self):
        self.assertFalse(_text_has_db_error_markers('{"status":"success","data":[]}'))


class InferredContentTypeTests(unittest.TestCase):
    def test_json_body_without_content_type(self):
        self.assertEqual(_inferred_content_type_for_body('{"a":1}', ""), "application/json")
        self.assertEqual(_inferred_content_type_for_body('  [1,2]', ""), "application/json")

    def test_form_body_without_content_type(self):
        self.assertEqual(
            _inferred_content_type_for_body("a=1&b=2", ""), "application/x-www-form-urlencoded"
        )

    def test_existing_content_type_returns_none(self):
        self.assertIsNone(_inferred_content_type_for_body('{"a":1}', "application/json"))
        self.assertIsNone(_inferred_content_type_for_body('{"a":1}', "text/plain"))

    def test_empty_body_returns_none(self):
        self.assertIsNone(_inferred_content_type_for_body("", ""))


class BooleanProbeFallbackTests(unittest.IsolatedAsyncioTestCase):
    def _validator(self):
        return SqlmapValidator(binary="sqlmap")

    async def test_run_context_actual_probe_preserves_session_and_budget(self):
        fixture = _Fixture()
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=2,
                                gate_config={"active_enabled": True})
        ctx.sessions.register("user", "user", {"Authorization": "Bearer sql"},
                              allowed_origins=[ScopePolicy.origin_of(fixture.base)])
        validator = SqlmapValidator(
            binary="sqlmap", run_context=ctx)
        exchange = HttpExchange(
            url=fixture.base + "/search?q=one", method="GET",
            request_headers={"Authorization": "Bearer sql"}, response_status=200)
        try:
            result = await validator._boolean_probe_fallback(_finding(), exchange)
            self.assertEqual(result.status, "not_confirmed")
            self.assertEqual(ctx.budget.used, 2)
            self.assertEqual(len(fixture.httpd.received), 2)
            self.assertTrue(all(r["authorization"] == "Bearer sql"
                                for r in fixture.httpd.received))
        finally:
            await ctx.aclose()
            fixture.close()

    async def test_run_context_denied_mutating_probe_sends_nothing(self):
        fixture = _Fixture()
        ctx = RunContext.create(
            allowed_hosts=["127.0.0.1"], max_requests=2,
            gate_config={"active_enabled": True, "allow_mutating_replay": False})
        validator = SqlmapValidator(binary="sqlmap", run_context=ctx)
        exchange = HttpExchange(
            url=fixture.base + "/search", method="POST",
            request_headers={"Content-Type": "application/json"},
            request_body='{"q":"one"}', response_status=200)
        try:
            result = await validator._boolean_probe_fallback(_finding(), exchange)
            self.assertEqual(result.status, "error")
            self.assertEqual(ctx.budget.used, 0)
            self.assertEqual(fixture.httpd.received, [])
        finally:
            await ctx.aclose()
            fixture.close()

    async def test_no_mutable_parameter_returns_none_without_any_network_call(self):
        v = self._validator()
        exchange = HttpExchange(url="https://x.test/health", method="GET")
        with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_req:
            result = await v._boolean_probe_fallback(_finding(), exchange)
        mock_req.assert_not_called()
        self.assertIsNone(result)

    async def test_empty_header_capture_gets_json_content_type(self):
        """Regression (Juice Shop full-run sqlmap 0/26 diagnosis): a capture
        with request_headers={} and a JSON body was replayed with NO
        Content-Type, so express.json() never parsed it, req.body was empty,
        and every payload returned an identical unparsed-body response --
        making the differential silently impossible. The probe must now add
        Content-Type: application/json for a JSON-shaped body."""
        v = self._validator()
        exchange = HttpExchange(
            url="http://localhost:3000/rest/user/login", method="POST",
            request_headers={},  # <-- as captured in the real run
            request_body='{"email":"a@b.com","password":"x"}',
            response_status=200,
        )
        resp_a = httpx.Response(200, content=b"x" * 500, request=httpx.Request("POST", exchange.url))
        resp_b = httpx.Response(401, content=b"y" * 5, request=httpx.Request("POST", exchange.url))
        with patch("httpx.AsyncClient.request", new_callable=AsyncMock,
                   side_effect=[resp_a, resp_b]) as mock_req:
            result = await v._boolean_probe_fallback(_finding(), exchange)
        self.assertEqual(result.status, "confirmed")
        # Every replayed request must carry the JSON Content-Type.
        for call in mock_req.call_args_list:
            headers = call.kwargs.get("headers", {})
            ct = next((val for k, val in headers.items() if k.lower() == "content-type"), None)
            self.assertEqual(ct, "application/json")

    async def test_existing_content_type_is_not_overwritten(self):
        """A capture that already declared a content-type is left exactly as
        sent -- the fix only fills in a MISSING header."""
        v = self._validator()
        exchange = HttpExchange(
            url="http://localhost:3000/api/search", method="POST",
            request_headers={"Content-Type": "application/vnd.custom+json"},
            request_body='{"query":"widgets"}', response_status=200,
        )
        resp_a = httpx.Response(200, content=b"x" * 500, request=httpx.Request("POST", exchange.url))
        resp_b = httpx.Response(200, content=b"x" * 5, request=httpx.Request("POST", exchange.url))
        with patch("httpx.AsyncClient.request", new_callable=AsyncMock,
                   side_effect=[resp_a, resp_b]) as mock_req:
            await v._boolean_probe_fallback(_finding(), exchange)
        headers = mock_req.call_args_list[0].kwargs.get("headers", {})
        ct = next((val for k, val in headers.items() if k.lower() == "content-type"), None)
        self.assertEqual(ct, "application/vnd.custom+json")

    async def test_json_body_field_differential_confirms(self):
        """The general case the credential-only version of this fallback
        could not handle: SQLi in an ordinary, non-auth JSON body field."""
        v = self._validator()
        exchange = _login_exchange(body='{"query":"widgets"}', url="http://localhost:3000/api/search")
        resp_a = httpx.Response(200, content=b"x" * 500, request=httpx.Request("POST", exchange.url))
        resp_b = httpx.Response(200, content=b"x" * 5, request=httpx.Request("POST", exchange.url))
        with patch("httpx.AsyncClient.request", new_callable=AsyncMock, side_effect=[resp_a, resp_b]):
            result = await v._boolean_probe_fallback(_finding(), exchange)
        self.assertEqual(result.status, "confirmed")
        self.assertTrue(result.confirmed)
        self.assertIn("body:query", result.summary)

    async def test_query_string_param_differential_confirms(self):
        """SQLi via a GET query-string parameter (e.g. ?id=1), the other
        classic non-auth case."""
        v = self._validator()
        exchange = HttpExchange(url="https://x.test/api/products?id=1", method="GET")
        resp_a = httpx.Response(200, request=httpx.Request("GET", exchange.url))
        resp_b = httpx.Response(500, request=httpx.Request("GET", exchange.url))
        with patch("httpx.AsyncClient.request", new_callable=AsyncMock, side_effect=[resp_a, resp_b]):
            result = await v._boolean_probe_fallback(_finding(), exchange)
        self.assertEqual(result.status, "confirmed")
        self.assertIn("query:id", result.summary)

    async def test_second_parameter_confirms_when_first_is_not_injectable(self):
        v = self._validator()
        exchange = HttpExchange(url="https://x.test/api/products?id=1&category=tools", method="GET")
        id_a = httpx.Response(200, request=httpx.Request("GET", exchange.url))
        id_b = httpx.Response(200, request=httpx.Request("GET", exchange.url))
        cat_a = httpx.Response(200, request=httpx.Request("GET", exchange.url))
        cat_b = httpx.Response(401, request=httpx.Request("GET", exchange.url))
        with patch("httpx.AsyncClient.request", new_callable=AsyncMock,
                   side_effect=[id_a, id_b, cat_a, cat_b]):
            result = await v._boolean_probe_fallback(_finding(), exchange)
        self.assertEqual(result.status, "confirmed")
        self.assertIn("query:category", result.summary)

    async def test_error_signature_confirms_when_boolean_differential_does_not(self):
        """The exact real gap found live against Juice Shop's product
        search: a LIKE '%...%'-wrapped parameter where OR-based tautology
        and contradiction both return identical (all-matching) results --
        no boolean differential -- but the tautology payload's trailing
        syntax produces a genuine, visible database error. Must still
        confirm via the error signature, not report not_confirmed."""
        v = self._validator()
        exchange = HttpExchange(
            url="http://localhost:3000/rest/products/search?q=apple", method="GET",
            response_status=200, response_body='{"status":"success","data":[]}',
        )
        resp_a = httpx.Response(
            500, content=b"Error: SQLITE_ERROR: incomplete input",
            request=httpx.Request("GET", exchange.url),
        )
        resp_b = httpx.Response(
            500, content=b"Error: SQLITE_ERROR: incomplete input",
            request=httpx.Request("GET", exchange.url),
        )
        with patch("httpx.AsyncClient.request", new_callable=AsyncMock, side_effect=[resp_a, resp_b]):
            result = await v._boolean_probe_fallback(_finding(), exchange)
        self.assertEqual(result.status, "confirmed")
        self.assertTrue(result.confirmed)
        self.assertIn("Error-based", result.summary)

    async def test_baseline_already_erroring_endpoint_is_not_flagged(self):
        """An endpoint that already returns DB-error-shaped text for
        ordinary input (broken independent of injection) must not be
        flagged just for continuing to error under a mutated value."""
        v = self._validator()
        exchange = HttpExchange(
            url="http://localhost:3000/rest/products/search?q=apple", method="GET",
            response_status=500, response_body="Error: SQLITE_ERROR: something already broken",
        )
        resp_a = httpx.Response(
            500, content=b"Error: SQLITE_ERROR: something already broken",
            request=httpx.Request("GET", exchange.url),
        )
        resp_b = httpx.Response(
            500, content=b"Error: SQLITE_ERROR: something already broken",
            request=httpx.Request("GET", exchange.url),
        )
        with patch("httpx.AsyncClient.request", new_callable=AsyncMock, side_effect=[resp_a, resp_b]):
            result = await v._boolean_probe_fallback(_finding(), exchange)
        self.assertEqual(result.status, "not_confirmed")

    async def test_no_differential_on_any_parameter_does_not_confirm(self):
        v = self._validator()
        exchange = HttpExchange(url="https://x.test/api/products?id=1&category=tools", method="GET")
        resp_200 = httpx.Response(200, request=httpx.Request("GET", exchange.url))
        with patch("httpx.AsyncClient.request", new_callable=AsyncMock,
                   side_effect=[resp_200, resp_200, resp_200, resp_200]):
            result = await v._boolean_probe_fallback(_finding(), exchange)
        self.assertEqual(result.status, "not_confirmed")
        self.assertFalse(result.confirmed)

    async def test_network_failure_on_every_parameter_returns_error_not_a_false_negative(self):
        v = self._validator()
        exchange = HttpExchange(url="https://x.test/api/products?id=1", method="GET")
        with patch("httpx.AsyncClient.request", new_callable=AsyncMock,
                   side_effect=httpx.ConnectError("refused")):
            result = await v._boolean_probe_fallback(_finding(), exchange)
        self.assertEqual(result.status, "error")
        self.assertFalse(result.confirmed)

    async def test_probes_are_capped_at_max_probe_params(self):
        v = self._validator()
        url = "https://x.test/api/x?" + "&".join(f"p{i}=v{i}" for i in range(10))
        exchange = HttpExchange(url=url, method="GET")
        resp_200 = httpx.Response(200, request=httpx.Request("GET", url))
        with patch("httpx.AsyncClient.request", new_callable=AsyncMock, return_value=resp_200) as mock_req:
            await v._boolean_probe_fallback(_finding(), exchange)
        self.assertLessEqual(mock_req.call_count, v._MAX_PROBE_PARAMS * 2)


class SqlmapValidatorFallsBackWhenBinaryMissingTests(unittest.IsolatedAsyncioTestCase):
    """End-to-end through validate() itself, not just the helper -- proves
    the FileNotFoundError path (sqlmap not installed, the exact real
    condition found live this session) actually reaches the fallback
    rather than just returning the old bare error."""

    def setUp(self):
        reset_default_gate()
        get_default_gate({"active_enabled": True, "allow_mutating_replay": True})

    def tearDown(self):
        reset_default_gate()

    async def test_missing_binary_falls_back_to_boolean_probe(self):
        v = SqlmapValidator(binary="definitely-not-a-real-sqlmap-binary-xyz")
        exchange = _login_exchange()
        resp_a = httpx.Response(200, request=httpx.Request("POST", exchange.url))
        resp_b = httpx.Response(401, request=httpx.Request("POST", exchange.url))
        with patch("httpx.AsyncClient.request", new_callable=AsyncMock, side_effect=[resp_a, resp_b]):
            result = await v.validate(_finding(), exchange)
        self.assertEqual(result.status, "confirmed")
        self.assertTrue(result.confirmed)

    async def test_missing_binary_with_no_mutable_parameter_reports_plain_error(self):
        v = SqlmapValidator(binary="definitely-not-a-real-sqlmap-binary-xyz")
        exchange = HttpExchange(url="http://localhost:3000/rest/user/whoami", method="GET")
        result = await v.validate(_finding(), exchange)
        self.assertEqual(result.status, "error")
        self.assertIn("sqlmap executable not found", result.summary)


class AuthRequestDetectionTests(unittest.TestCase):
    def test_credential_body_field_is_auth(self):
        self.assertTrue(_looks_like_auth_request(_login_exchange()))

    def test_auth_path_segment_is_auth(self):
        for p in ("/account/login", "/oauth/token", "/api/session", "/v1/authenticate", "/signin"):
            ex = HttpExchange(url=f"https://x.test{p}", method="POST", request_body="")
            self.assertTrue(_looks_like_auth_request(ex), p)

    def test_non_auth_is_not_flagged(self):
        # "authors"/"passengers" must NOT substring-match "auth"/"pass".
        cases = [("https://x.test/api/authors", "GET", ""),
                 ("https://x.test/api/passengers", "POST", '{"name":"x"}'),
                 ("https://x.test/api/products?id=1", "GET", "")]
        for url, method, body in cases:
            ex = HttpExchange(url=url, method=method, request_body=body)
            self.assertFalse(_looks_like_auth_request(ex), url)


class _FakeProc:
    def __init__(self, returncode=1, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class SqlmapAuthLoginTuningTests(unittest.IsolatedAsyncioTestCase):
    """HANDOVER_6 §3/§6.3: a valid-cred (2xx) login capture defeats sqlmap because
    its injection payloads flip the response to 401 and sqlmap skips non-2xx as
    'not testable'. Two fixes: tell sqlmap to ignore the auth-rejection codes, and
    fall back to the boolean-differential probe (which reads the 2xx<->401 flip
    directly) when sqlmap still misses."""

    def setUp(self):
        reset_default_gate()
        get_default_gate({"active_enabled": True, "allow_mutating_replay": True})

    def tearDown(self):
        reset_default_gate()

    async def test_ignore_code_includes_auth_rejection_codes_for_login(self):
        v = SqlmapValidator(binary="sqlmap")
        exchange = _login_exchange()  # POST, 2xx baseline, password field
        same = httpx.Response(200, content=b"x" * 100, request=httpx.Request("POST", exchange.url))
        with patch("validators.sqlmap.subprocess.run",
                   return_value=_FakeProc(returncode=1, stdout="not vulnerable")), \
             patch("httpx.AsyncClient.request", new_callable=AsyncMock, return_value=same):
            result = await v.validate(_finding(), exchange)
        self.assertIn("--ignore-code", result.command)
        codes = result.command[result.command.index("--ignore-code") + 1]
        self.assertIn("401", codes)
        self.assertIn("403", codes)

    async def test_boolean_probe_secondary_confirms_when_sqlmap_misses_login(self):
        v = SqlmapValidator(binary="sqlmap")
        exchange = _login_exchange()
        big = httpx.Response(200, content=b"x" * 500, request=httpx.Request("POST", exchange.url))
        small = httpx.Response(401, content=b"y" * 5, request=httpx.Request("POST", exchange.url))
        with patch("validators.sqlmap.subprocess.run",
                   return_value=_FakeProc(returncode=1, stdout="not vulnerable")), \
             patch("httpx.AsyncClient.request", new_callable=AsyncMock, side_effect=[big, small]):
            result = await v.validate(_finding(), exchange)
        self.assertEqual(result.status, "confirmed")
        self.assertTrue(result.confirmed)
        self.assertIn("boolean-differential probe", result.summary)

    async def test_sqlmap_confirmation_is_not_overridden_by_secondary(self):
        # If sqlmap DOES confirm, that result stands -- the secondary never runs.
        v = SqlmapValidator(binary="sqlmap")
        exchange = _login_exchange()
        with patch("validators.sqlmap.subprocess.run",
                   return_value=_FakeProc(returncode=0, stdout="parameter is vulnerable")), \
             patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_req:
            result = await v.validate(_finding(), exchange)
        self.assertEqual(result.status, "confirmed")
        self.assertIn("sqlmap independently reported", result.summary)
        mock_req.assert_not_called()  # secondary probe never fired

    async def test_non_auth_endpoint_gets_no_auth_rejection_codes(self):
        v = SqlmapValidator(binary="sqlmap")
        url = "https://x.test/api/products?id=1"
        exchange = HttpExchange(url=url, method="GET", response_status=200)
        with patch("validators.sqlmap.subprocess.run",
                   return_value=_FakeProc(returncode=1, stdout="not vulnerable")):
            result = await v.validate(_finding(), exchange)
        self.assertNotIn("--ignore-code", result.command)


if __name__ == "__main__":
    unittest.main()
