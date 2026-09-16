"""
Tests for the fast-path agent selection module.

These tests verify:
1. Fast-path selection works for various patterns
2. Selection is always a subset of available agents
3. Early termination logic works correctly
4. Pattern matching is accurate
5. Stats tracking works
"""
import unittest
from harness.models import HttpExchange, AgentReport, Finding
from harness.fast_path import (
    select_agents_by_url,
    select_agents_by_query_params,
    select_agents_by_request_headers,
    select_agents_by_method,
    select_agents_by_status,
    select_agents_by_response_body,
    select_agents_by_response_headers,
    select_agents_by_csrf_signal,
    select_fast_path_agents,
    should_terminate_early,
    EarlyTerminationConfig,
    FastPathSelector,
    _URL_PATTERNS,
    _QUERY_PARAM_PATTERNS,
)


class TestUrlPatterns(unittest.TestCase):
    """Test URL pattern matching."""
    
    def test_graphql_endpoint(self):
        """GraphQL endpoints should select sqli, idor, business_logic."""
        agents = select_agents_by_url("/api/graphql")
        self.assertIn("sqli", agents)
        self.assertIn("idor", agents)
        self.assertIn("business_logic", agents)
    
    def test_admin_endpoint(self):
        """Admin endpoints should select auth, idor, misconfig."""
        agents = select_agents_by_url("/admin/users")
        self.assertIn("auth", agents)
        self.assertIn("idor", agents)
        self.assertIn("misconfig", agents)
    
    def test_login_endpoint(self):
        """Login endpoints should select auth, business_logic, sqli --
        credential fields are a classic SQLi injection point, found
        missing during a real scoring pass against testing/test-target/."""
        agents = select_agents_by_url("/login")
        self.assertIn("auth", agents)
        self.assertIn("business_logic", agents)
        self.assertIn("sqli", agents)
    
    def test_api_endpoint(self):
        """API endpoints should select multiple agents."""
        agents = select_agents_by_url("/api/v1/users")
        self.assertGreaterEqual(len(agents), 3)
    
    def test_upload_endpoint(self):
        """Upload endpoints should select xss, misconfig, supply_chain."""
        agents = select_agents_by_url("/upload")
        self.assertIn("xss", agents)
        self.assertIn("misconfig", agents)
        self.assertIn("supply_chain", agents)
    
    def test_user_endpoint(self):
        """User endpoints should select idor, auth, misconfig."""
        agents = select_agents_by_url("/users/123")
        self.assertIn("idor", agents)
        self.assertIn("auth", agents)
        self.assertIn("misconfig", agents)
    
    def test_track_order_idor(self):
        """track-order endpoints carry the numeric-id-in-path IDOR shape
        (Juice Shop full-run dispatch gap): must select idor/auth/misconfig
        even though the path lacks a bare '/order' substring."""
        agents = select_agents_by_url("/rest/track-order/5")
        self.assertIn("idor", agents)
        self.assertIn("auth", agents)
        self.assertIn("misconfig", agents)

    def test_ftp_directory_listing(self):
        """Exposed file-store endpoints (Juice Shop /ftp) must select
        misconfig/recon/info_disclosure -- previously matched nothing."""
        agents = select_agents_by_url("/ftp")
        self.assertIn("misconfig", agents)
        self.assertIn("recon", agents)
        self.assertIn("info_disclosure", agents)
        # A path segment under /ftp should also match.
        self.assertIn("recon", select_agents_by_url("/ftp/package.json.bak"))

    def test_unknown_endpoint(self):
        """Unknown endpoints should return empty set."""
        agents = select_agents_by_url("/completely/unknown/path")
        self.assertEqual(len(agents), 0)
    
    def test_case_insensitive_matching(self):
        """Pattern matching should be case-insensitive."""
        agents_lower = select_agents_by_url("/api/graphql")
        agents_upper = select_agents_by_url("/API/GRAPHQL")
        self.assertEqual(agents_lower, agents_upper)


class TestQueryParamPatterns(unittest.TestCase):
    """Test query parameter pattern matching."""
    
    def test_id_parameter(self):
        """ID parameters should select idor, sqli."""
        agents = select_agents_by_query_params("id=123&name=test")
        self.assertIn("idor", agents)
        self.assertIn("sqli", agents)
    
    def test_search_parameter(self):
        """Search parameters should select sqli, xss."""
        agents = select_agents_by_query_params("q=test&page=1")
        self.assertIn("sqli", agents)
        self.assertIn("xss", agents)
    
    def test_file_parameter(self):
        """File parameters should select ssrf, misconfig."""
        agents = select_agents_by_query_params("file=/etc/passwd")
        self.assertIn("ssrf", agents)
        self.assertIn("misconfig", agents)
    
    def test_token_parameter(self):
        """Token parameters should select auth, misconfig."""
        agents = select_agents_by_query_params("token=abc123")
        self.assertIn("auth", agents)
        self.assertIn("misconfig", agents)
    
    def test_empty_query_string(self):
        """Empty query string should return empty set."""
        agents = select_agents_by_query_params("")
        self.assertEqual(len(agents), 0)

    def test_unrecognized_param_name_still_gets_sqli_xss_baseline(self):
        """Regression test: a search-shaped parameter using a name that
        isn't in the recognized category list (e.g. 's=', 'text=') must
        still get sqli/xss -- any parameter value is untrusted input
        regardless of its name. This was a real gap: after removing the
        GET-method blanket, only recognized param names got sqli/xss,
        so '?s=apple' silently lost fast-path coverage it used to get
        (for the wrong reason) from the old blanket. See
        FAST_PATH_EFFICIENCY.md, "known-param-name gap"."""
        agents = select_agents_by_query_params("s=apple")
        self.assertIn("sqli", agents)
        self.assertIn("xss", agents)

        agents = select_agents_by_query_params("text=apple")
        self.assertIn("sqli", agents)
        self.assertIn("xss", agents)

    def test_any_query_param_also_gets_anomaly_baseline(self):
        """Regression test for a real scoring gap against
        testing/test-target/: a path-traversal exchange (`?file=../app.py`)
        dispatched 8 LLM-backed agents, none of which correctly named the
        vulnerability, while `anomaly` -- never dispatched at all -- would
        have matched the `../` pattern deterministically (see
        anomaly_detector.py's suspicious_patterns) at zero additional
        Ollama cost, since its run() bypasses the LLM pipeline entirely."""
        agents = select_agents_by_query_params("file=../app.py")
        self.assertIn("anomaly", agents)


class TestMethodPatterns(unittest.TestCase):
    """Test HTTP method pattern matching."""
    
    def test_get_method(self):
        """GET carries no independent signal -- it's the majority of all
        traffic, so mapping it to agents would make method a blanket floor
        rather than evidence. URL/query/header/body patterns do that work."""
        agents = select_agents_by_method("GET")
        self.assertEqual(len(agents), 0)

    def test_post_method(self):
        """POST likewise carries no independent signal, for the same reason
        (it's the second most common method; content-type/body patterns
        already cover what POST bodies actually reveal)."""
        agents = select_agents_by_method("POST")
        self.assertEqual(len(agents), 0)

    def test_delete_method(self):
        """DELETE is state-mutating: keep the narrow, evidence-independent
        authorization heuristic (idor, auth) but not a blanket list."""
        agents = select_agents_by_method("DELETE")
        self.assertIn("idor", agents)
        self.assertIn("auth", agents)
        self.assertEqual(agents, {"idor", "auth"})
    
    def test_head_method(self):
        """HEAD should select misconfig."""
        agents = select_agents_by_method("HEAD")
        self.assertIn("misconfig", agents)
    
    def test_unknown_method(self):
        """Unknown methods should return empty set."""
        agents = select_agents_by_method("UNKNOWN")
        self.assertEqual(len(agents), 0)


class TestStatusPatterns(unittest.TestCase):
    """Test response status code pattern matching."""
    
    def test_200_status(self):
        """200 is the overwhelming majority of responses and carries no
        discriminating information on its own -- it should not contribute
        any agents (URL/query/header/body patterns do the real work)."""
        agents = select_agents_by_status(200)
        self.assertEqual(len(agents), 0)
    
    def test_401_status(self):
        """401 should select auth, misconfig."""
        agents = select_agents_by_status(401)
        self.assertIn("auth", agents)
        self.assertIn("misconfig", agents)
    
    def test_403_status(self):
        """403 should select auth, idor, misconfig."""
        agents = select_agents_by_status(403)
        self.assertIn("auth", agents)
        self.assertIn("idor", agents)
        self.assertIn("misconfig", agents)
    
    def test_500_status(self):
        """500 should select misconfig, supply_chain."""
        agents = select_agents_by_status(500)
        self.assertIn("misconfig", agents)
        self.assertIn("supply_chain", agents)
    
    def test_none_status(self):
        """None status should return empty set."""
        agents = select_agents_by_status(None)
        self.assertEqual(len(agents), 0)


class TestResponseBodyPatterns(unittest.TestCase):
    """Test response body pattern matching."""
    
    def test_sql_error(self):
        """SQL errors should select sqli."""
        agents = select_agents_by_response_body("SQL syntax error near 'OR'")
        self.assertIn("sqli", agents)
    
    def test_stack_trace(self):
        """Stack traces should select misconfig, supply_chain."""
        agents = select_agents_by_response_body("at com.example.Service.method(Service.java:42)")
        self.assertIn("misconfig", agents)
        self.assertIn("supply_chain", agents)
    
    def test_version_banner(self):
        """Version banners should select misconfig, supply_chain."""
        agents = select_agents_by_response_body("Apache/2.4.41")
        self.assertIn("misconfig", agents)
        self.assertIn("supply_chain", agents)
    
    def test_html_response(self):
        """HTML responses should select xss, misconfig."""
        agents = select_agents_by_response_body("<html><body>Test</body></html>")
        self.assertIn("xss", agents)
        self.assertIn("misconfig", agents)
    
    def test_empty_body(self):
        """Empty body should return empty set."""
        agents = select_agents_by_response_body("")
        self.assertEqual(len(agents), 0)


class TestRequestHeaderPatterns(unittest.TestCase):
    """Test request header pattern matching."""
    
    def test_json_content_type(self):
        """JSON content type should select multiple agents."""
        headers = {"Content-Type": "application/json"}
        agents = select_agents_by_request_headers(headers)
        self.assertIn("sqli", agents)
        self.assertIn("xss", agents)
    
    def test_form_content_type(self):
        """Form content type should select sqli, xss, idor."""
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        agents = select_agents_by_request_headers(headers)
        self.assertIn("sqli", agents)
        self.assertIn("xss", agents)
        self.assertIn("idor", agents)
    
    def test_authorization_header(self):
        """Authorization header should select auth."""
        headers = {"Authorization": "Bearer token123"}
        agents = select_agents_by_request_headers(headers)
        self.assertIn("auth", agents)
    
    def test_basic_auth_header(self):
        """Basic auth header should select auth."""
        headers = {"Authorization": "Basic dXNlcjpwYXNz"}
        agents = select_agents_by_request_headers(headers)
        self.assertIn("auth", agents)


class TestJwtAndCsrfFastPathCoverage(unittest.TestCase):
    """
    Regression tests for a real gap found during the testing/test-target/
    discovery run: jwt and csrf had ZERO fast_path entries anywhere (URL,
    header, or body tables), so they could only be reached via the
    coordinator -- which fast_path being confident on nearly every real
    exchange meant essentially never happened in practice (confirmed:
    never fired once across a full discovery run). See HANDOVER.md.
    """

    def test_jwt_shaped_bearer_token_selects_jwt_and_auth(self):
        headers = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9."
                              "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
                              "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        }
        agents = select_agents_by_request_headers(headers)
        self.assertIn("jwt", agents)
        self.assertIn("auth", agents)

    def test_jwt_shaped_token_in_cookie_also_selects_jwt(self):
        """A JWT can be carried in a session cookie instead of
        Authorization -- the pattern isn't gated to one header name."""
        headers = {
            "Cookie": "session=eyJhbGciOiJIUzI1NiJ9."
                      "eyJ1c2VyIjoiYWxpY2UifQ."
                      "c2lnbmF0dXJl"
        }
        agents = select_agents_by_request_headers(headers)
        self.assertIn("jwt", agents)

    def test_alg_none_forged_token_with_empty_signature_still_selects_jwt(self):
        """The single highest-value real case this pattern exists to
        catch: an alg:none forged token has an EMPTY signature segment
        (no signature at all), so the JWT ends immediately after the
        second dot. A trailing `\\b` would fail to match here (confirmed
        directly) since neither neighbor of that position is a word
        character -- this is testing/test-target/'s real TP11 scenario."""
        headers = {
            "Authorization": "Bearer eyJhbGciOiJub25lIn0."
                              "eyJ1c2VyX2lkIjozLCJyb2xlIjoiYWRtaW4ifQ."
        }
        agents = select_agents_by_request_headers(headers)
        self.assertIn("jwt", agents)

    def test_non_jwt_bearer_token_does_not_select_jwt(self):
        """An opaque (non-JWT) bearer token should still select auth
        (existing behavior) but must not falsely claim jwt."""
        headers = {"Authorization": "Bearer opaque-session-token-abc123"}
        agents = select_agents_by_request_headers(headers)
        self.assertIn("auth", agents)
        self.assertNotIn("jwt", agents)

    def test_state_changing_request_with_cookie_selects_csrf(self):
        agents = select_agents_by_csrf_signal("POST", {"Cookie": "session=abc123"})
        self.assertEqual(agents, {"csrf"})

    def test_put_with_cookie_selects_csrf(self):
        agents = select_agents_by_csrf_signal("PUT", {"Cookie": "session=abc123"})
        self.assertEqual(agents, {"csrf"})

    def test_get_request_never_selects_csrf(self):
        """GET is not state-changing -- CSRF doesn't apply regardless of
        cookie presence."""
        agents = select_agents_by_csrf_signal("GET", {"Cookie": "session=abc123"})
        self.assertEqual(agents, set())

    def test_state_changing_request_without_cookie_does_not_select_csrf(self):
        """Bearer/API-key auth isn't cookie-based and isn't in CSRF's
        threat model -- no Cookie header means no CSRF precondition."""
        agents = select_agents_by_csrf_signal("POST", {"Authorization": "Bearer abc123"})
        self.assertEqual(agents, set())

    def test_full_selection_dispatches_jwt_for_jwt_shaped_auth_header(self):
        """End-to-end: select_fast_path_agents (the real dispatch path)
        actually includes jwt, not just the lower-level header-matching
        function."""
        exchange = HttpExchange(
            url="https://example.com/api/users/3/profile",
            method="GET",
            request_headers={
                "Authorization": "Bearer eyJhbGciOiJub25lIn0."
                                  "eyJ1c2VyX2lkIjozLCJyb2xlIjoiYWRtaW4ifQ."
            },
            request_body="",
            response_status=200,
            response_headers={},
            response_body='{"email":"admin@example.com"}',
        )
        selected, reason = select_fast_path_agents(exchange, {"jwt", "auth", "idor", "misconfig"})
        self.assertIsNotNone(selected)
        self.assertIn("jwt", selected)

    def test_full_selection_dispatches_csrf_for_cookie_authenticated_post(self):
        exchange = HttpExchange(
            url="https://example.com/api/account/change-email",
            method="POST",
            request_headers={"Cookie": "session=abc123", "Content-Type": "application/json"},
            request_body='{"email": "new@example.com"}',
            response_status=200,
            response_headers={},
            response_body="",
        )
        selected, reason = select_fast_path_agents(exchange, {"csrf", "sqli", "xss", "idor", "business_logic"})
        self.assertIsNotNone(selected)
        self.assertIn("csrf", selected)


class TestClosedDispatchCoverageGaps(unittest.TestCase):
    """
    Regression tests for a real, live-observed gap: a systematic audit of
    all 36 registered agents against every fast_path dispatch table found
    10 with ZERO entries anywhere -- same disease as jwt/csrf (see
    TestJwtAndCsrfFastPathCoverage above), just never audited for the rest
    of the roster. Found live against a real Juice Shop
    `/redirect?to=<url>` request (the textbook open-redirect shape): fast
    path was confident enough on other grounds (ssrf/misconfig) that the
    coordinator was never even consulted, so open_redirect -- and
    header_injection, file_upload, xxe, command_injection, info_disclosure,
    rate_limit, nosql -- had no chance regardless of what the coordinator
    would have picked. business_logic_enhanced and ssti remain open
    (see HANDOVER.md): the former has no distinct precondition from
    business_logic to trigger on, and the latter has no sufficiently
    low-false-positive heuristic identified yet.
    """

    def test_redirect_target_query_param_selects_open_redirect_and_header_injection(self):
        """The actual real-world case: Juice Shop's own `to=` parameter,
        which the old pattern (file|path|url|uri|link|redirect|next|target)
        did not match at all."""
        agents = select_agents_by_query_params("to=https://github.com/juice-shop/juice-shop")
        self.assertIn("open_redirect", agents)
        self.assertIn("header_injection", agents)
        self.assertIn("ssrf", agents)

    def test_other_common_redirect_param_names_also_select_open_redirect(self):
        for query in ("return_to=/dashboard", "returnurl=/dashboard", "dest=/dashboard",
                      "continue=/dashboard", "goto=/dashboard", "redir=/dashboard",
                      "out=/dashboard", "forward=/dashboard"):
            agents = select_agents_by_query_params(query)
            self.assertIn("open_redirect", agents, f"expected open_redirect for {query!r}")

    def test_short_param_names_do_not_false_positive_on_unrelated_words(self):
        """'to'/'out' are common substrings of unrelated words -- must be
        boundary-matched, not bare substrings, or e.g. 'token'/'checkout'
        would falsely trigger open_redirect."""
        agents = select_agents_by_query_params("token=abc123&checkout=1&custom=x")
        self.assertNotIn("open_redirect", agents)

    def test_multipart_form_data_selects_file_upload(self):
        agents = select_agents_by_request_headers({"Content-Type": "multipart/form-data; boundary=----X"})
        self.assertIn("file_upload", agents)

    def test_xml_content_type_selects_xxe(self):
        agents = select_agents_by_request_headers({"Content-Type": "application/xml"})
        self.assertIn("xxe", agents)

    def test_command_param_name_selects_command_injection(self):
        agents = select_agents_by_query_params("cmd=ls")
        self.assertIn("command_injection", agents)

    def test_discovery_file_response_selects_info_disclosure(self):
        agents = select_agents_by_response_body("# Project\n\nSee .env for config, .git/ for history")
        self.assertIn("info_disclosure", agents)

    def test_stack_trace_response_selects_info_disclosure(self):
        agents = select_agents_by_response_body('Traceback (most recent call last):\n  File "app.py", line 42')
        self.assertIn("info_disclosure", agents)

    def test_login_endpoint_selects_rate_limit(self):
        agents = select_agents_by_url("/login")
        self.assertIn("rate_limit", agents)

    def test_json_content_type_selects_nosql(self):
        agents = select_agents_by_request_headers({"Content-Type": "application/json"})
        self.assertIn("nosql", agents)

    def test_basket_shaped_url_dispatches_idor(self):
        """Found live against a real Juice Shop GET /rest/basket/<id>
        request -- exactly the same per-user-owned, sequential-id-in-URL
        shape as order/invoice/booking (already covered), just a
        different noun. idor was not dispatched at all for it."""
        agents = select_agents_by_url("/rest/basket/1")
        self.assertIn("idor", agents)

    def test_file_upload_url_selects_file_upload_agent(self):
        """Found live against a real Juice Shop POST /file-upload request:
        this URL pattern already matched (xss/misconfig/supply_chain
        fired), but never included the one agent built to test uploads."""
        agents = select_agents_by_url("/file-upload")
        self.assertIn("file_upload", agents)


class TestFastPathSelection(unittest.TestCase):
    """Test complete fast-path agent selection."""
    
    def test_graphql_endpoint_selection(self):
        """GraphQL endpoint should select agents without coordinator."""
        exchange = HttpExchange(
            url="https://example.com/graphql",
            method="POST",
            request_headers={"Content-Type": "application/json"},
            request_body='{"query": "{ users { id } }"}',
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"data": {"users": []}}',
        )
        
        available = {"sqli", "xss", "idor", "ssrf", "auth", "business_logic", "misconfig"}
        result = select_fast_path_agents(exchange, available)
        
        self.assertIsNotNone(result[0])
        self.assertIn("sqli", result[0])
        self.assertIn("idor", result[0])
        self.assertIn("URL pattern", result[1])
    
    def test_login_endpoint_selection(self):
        """Login endpoint should select auth, business_logic, sqli."""
        exchange = HttpExchange(
            url="https://example.com/login",
            method="POST",
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            request_body="username=test&password=test",
            response_status=200,
            response_headers={},
            response_body="",
        )

        available = {"sqli", "xss", "idor", "ssrf", "auth", "business_logic", "misconfig"}
        result = select_fast_path_agents(exchange, available)

        self.assertIsNotNone(result[0])
        self.assertIn("auth", result[0])
        self.assertIn("business_logic", result[0])
        self.assertIn("sqli", result[0])
    
    def test_sql_error_response_selection(self):
        """SQL error in response should select sqli."""
        exchange = HttpExchange(
            url="https://example.com/api/users",
            method="GET",
            request_headers={},
            request_body="",
            response_status=500,
            response_headers={"Content-Type": "text/html"},
            response_body="SQL syntax error near 'OR'",
        )
        
        available = {"sqli", "xss", "idor"}
        result = select_fast_path_agents(exchange, available)
        
        self.assertIsNotNone(result[0])
        self.assertIn("sqli", result[0])
    
    def test_no_match_falls_back_to_coordinator(self):
        """Unknown patterns should fall back to coordinator."""
        exchange = HttpExchange(
            url="https://example.com/completely/unknown",
            method="GET",
            request_headers={},
            request_body="",
            response_status=200,
            response_headers={},
            response_body="Unknown content",
        )
        
        available = {"sqli", "xss"}
        result = select_fast_path_agents(exchange, available)
        
        self.assertIsNone(result[0])
        self.assertEqual(result[1], "")
    
    def test_available_agents_filtering(self):
        """Selected agents should be filtered by available agents."""
        exchange = HttpExchange(
            url="https://example.com/graphql",
            method="POST",
            request_headers={},
            request_body="",
            response_status=200,
            response_headers={},
            response_body="",
        )
        
        # Only sqli is available
        available = {"sqli"}
        result = select_fast_path_agents(exchange, available)
        
        self.assertIsNotNone(result[0])
        self.assertEqual(result[0], ["sqli"])

    def test_generic_200_get_no_longer_hits_the_old_blanket_floor(self):
        """Regression test for the over-dispatch fix: a GET/200 exchange
        whose only signal is a generic HTML body should select just the
        agents that signal actually implies (xss, misconfig from the body
        pattern) -- not the old 6-agent floor from GET+200 stacking on
        top of it. See FAST_PATH_EFFICIENCY.md."""
        exchange = HttpExchange(
            url="https://example.com/foo/bar/baz",
            method="GET",
            request_headers={"Accept": "text/html"},
            request_body="",
            response_status=200,
            response_headers={"Content-Type": "text/html"},
            response_body="<html><body>hi</body></html>",
        )
        available = {"sqli", "xss", "idor", "misconfig", "auth", "business_logic"}
        result = select_fast_path_agents(exchange, available)

        self.assertIsNotNone(result[0])
        self.assertEqual(set(result[0]), {"xss", "misconfig"})

    def test_no_signal_get_200_falls_back_to_coordinator(self):
        """A GET/200 exchange with no URL/query/header/body signal at all
        should fall back to the coordinator, not dispatch anything from
        method/status alone -- confirms GET/200 no longer act as a floor."""
        exchange = HttpExchange(
            url="https://example.com/foo/bar/baz",
            method="GET",
            request_headers={},
            request_body="",
            response_status=200,
            response_headers={},
            response_body="plain text, nothing interesting",
        )
        available = {"sqli", "xss", "idor", "misconfig", "auth", "business_logic"}
        result = select_fast_path_agents(exchange, available)

        self.assertIsNone(result[0])

    def test_mutating_method_adds_authz_check_on_top_of_a_real_signal(self):
        """Method/status have never been standalone triggers here -- they
        only expand a selection once something else (URL/query/header/body)
        already established a strong signal (has_strong_signal). Given a
        real signal (an id-shaped query param, unrelated to authz), DELETE
        should still layer in the idor/auth heuristic on top of it, and
        that layering must survive the removal of the blanket method table."""
        exchange = HttpExchange(
            url="https://example.com/orders?order_id=42",
            method="DELETE",
            request_headers={},
            request_body="",
            response_status=200,
            response_headers={},
            response_body="",
        )
        available = {"sqli", "xss", "idor", "misconfig", "auth", "business_logic"}
        result = select_fast_path_agents(exchange, available)

        self.assertIsNotNone(result[0])
        self.assertIn("idor", result[0])
        self.assertIn("auth", result[0])
        # sqli comes from the id-shaped query param signal itself, not
        # from the method table -- confirms method added auth on top
        # rather than being the sole source of the selection.
        self.assertIn("sqli", result[0])

    def test_order_shaped_url_dispatches_idor(self):
        """Regression test for the PixelMart discovery run's architecture
        finding #2: /api/orders/<id> (a textbook IDOR shape -- sequential,
        per-user-owned resource ids) had no matching URL pattern at all,
        so idor never dispatched unless something else incidentally fired."""
        exchange = HttpExchange(
            url="https://example.com/api/orders/1",
            method="GET",
            request_headers={"Authorization": "Bearer x"},
            request_body="",
            response_status=200,
            response_headers={},
            response_body='{"id":1,"user_id":2,"total_price":69.0}',
        )
        available = {"sqli", "xss", "idor", "misconfig", "auth", "business_logic"}
        result = select_fast_path_agents(exchange, available)

        self.assertIsNotNone(result[0])
        self.assertIn("idor", result[0])

    def test_negative_quantity_in_response_dispatches_business_logic(self):
        """Regression test for architecture finding #3: a negative value
        in a money/quantity-shaped JSON field is a strong business-logic
        signal that no text pattern can match -- confirms the structural
        anomaly check fires even with no other matching signal present."""
        exchange = HttpExchange(
            url="https://example.com/api/orders",
            method="POST",
            request_headers={},
            request_body='{"product_id": 2, "quantity": -5}',
            response_status=200,
            response_headers={},
            response_body='{"status":"ordered","total_price":-399.95}',
        )
        available = {"sqli", "xss", "idor", "misconfig", "auth", "business_logic"}
        result = select_fast_path_agents(exchange, available)

        self.assertIsNotNone(result[0])
        self.assertIn("business_logic", result[0])

    def test_negative_quantity_in_request_body_also_dispatches_business_logic(self):
        """The anomaly check covers the request body too, not just the
        response -- a negative quantity is suspicious the moment it's
        sent, before the server even responds."""
        from harness.fast_path import select_agents_by_body_anomalies
        agents = select_agents_by_body_anomalies('{"quantity": -5}', "")
        self.assertIn("business_logic", agents)

    def test_positive_money_fields_do_not_trigger_anomaly(self):
        """A normal, positive price/quantity must not falsely trigger --
        this is a precision check on the new anomaly detector."""
        from harness.fast_path import select_agents_by_body_anomalies
        agents = select_agents_by_body_anomalies("", '{"total_price": 69.0, "quantity": 2}')
        self.assertEqual(agents, set())

    def test_negative_number_in_unrelated_field_does_not_trigger_anomaly(self):
        """A negative number in a field whose name has nothing to do
        with money or quantity (e.g. a temperature or a coordinate)
        must not trigger -- the field name match is what makes this
        precise rather than a blanket 'any negative number' rule."""
        from harness.fast_path import select_agents_by_body_anomalies
        agents = select_agents_by_body_anomalies("", '{"temperature_celsius": -5, "latitude": -12.3}')
        self.assertEqual(agents, set())

    def test_non_json_body_does_not_crash_anomaly_check(self):
        from harness.fast_path import select_agents_by_body_anomalies
        agents = select_agents_by_body_anomalies("not json at all", "<html>also not json</html>")
        self.assertEqual(agents, set())


class TestEarlyTermination(unittest.TestCase):
    """Test early termination logic."""
    
    def create_report(self, vulnerability_class: str, confidence: float, severity: str) -> AgentReport:
        """Helper to create test reports."""
        return AgentReport(
            agent="test_agent",
            model="test_model",
            findings=[
                Finding(
                    vulnerability_class=vulnerability_class,
                    confidence=confidence,
                    severity=severity,
                    summary="Test finding",
                    evidence="test",
                    suggested_test="test",
                    basis="derived",
                )
            ],
        )
    
    def test_early_termination_on_critical_finding(self):
        """Should terminate early on high-confidence critical finding."""
        config = EarlyTerminationConfig(
            enabled=True,
            min_confidence=0.9,
            min_severity={"critical", "high"},
            max_agents_before_check=2,
        )
        
        reports = [
            self.create_report("sqli", 0.95, "critical"),
            self.create_report("xss", 0.8, "medium"),
        ]
        
        result = should_terminate_early(reports, ["idor", "ssrf"], config)
        
        self.assertTrue(result[0])
        self.assertIn("critical", result[1])
    
    def test_no_early_termination_on_low_confidence(self):
        """Should not terminate early on low-confidence findings."""
        config = EarlyTerminationConfig(
            enabled=True,
            min_confidence=0.9,
            min_severity={"critical", "high"},
            max_agents_before_check=2,
        )
        
        reports = [
            self.create_report("sqli", 0.7, "high"),
            self.create_report("xss", 0.8, "medium"),
        ]
        
        result = should_terminate_early(reports, ["idor", "ssrf"], config)
        
        self.assertFalse(result[0])
    
    def test_no_early_termination_on_low_severity(self):
        """Should not terminate early on low-severity findings."""
        config = EarlyTerminationConfig(
            enabled=True,
            min_confidence=0.9,
            min_severity={"critical", "high"},
            max_agents_before_check=2,
        )
        
        reports = [
            self.create_report("sqli", 0.95, "medium"),
            self.create_report("xss", 0.9, "low"),
        ]
        
        result = should_terminate_early(reports, ["idor", "ssrf"], config)
        
        self.assertFalse(result[0])
    
    def test_early_termination_disabled(self):
        """Should not terminate early when disabled."""
        config = EarlyTerminationConfig(enabled=False)
        
        reports = [self.create_report("sqli", 0.95, "critical")]
        
        result = should_terminate_early(reports, ["idor"], config)
        
        self.assertFalse(result[0])
    
    def test_early_termination_min_agents(self):
        """Should not terminate before min agents have run."""
        config = EarlyTerminationConfig(
            enabled=True,
            min_confidence=0.9,
            min_severity={"critical", "high"},
            max_agents_before_check=5,
        )
        
        reports = [self.create_report("sqli", 0.95, "critical")]

        result = should_terminate_early(reports, ["idor", "xss", "ssrf", "auth"], config)

        self.assertFalse(result[0])

    def test_default_config_no_longer_terminates_on_high_severity_cors(self):
        """Regression test for a real, live bug: EarlyTerminationConfig's
        DEFAULT min_severity used to be {"critical", "high"} -- a real
        Juice Shop CORS misconfiguration finding (confidence 0.95, severity
        "high", which CORS reaches on nearly every exchange against that
        target) was silently cancelling the entire remaining agent batch,
        confirmed live via the orchestrator's own "Early termination: ..."
        log line: sqli/idor/xss/csp/misconfig/nosql/rate_limit never
        received an AgentReport at all across two full runs. The default
        is now {"critical"} only -- confirm the exact real scenario no
        longer terminates, using the actual default (no min_severity
        override), unlike every other test in this class."""
        config = EarlyTerminationConfig(enabled=True, min_confidence=0.9, max_agents_before_check=3)
        self.assertEqual(config.min_severity, {"critical"})

        reports = [
            self.create_report("auth", 0.6, "medium"),
            self.create_report("business_logic", 0.5, "medium"),
            self.create_report("cors", 0.95, "high"),
        ]
        result = should_terminate_early(reports, ["csp", "idor", "misconfig", "nosql", "rate_limit", "sqli", "xss"], config)
        self.assertFalse(result[0], f"must not terminate on a 'high' severity finding by default, got: {result}")

    def test_default_config_still_terminates_on_critical(self):
        """The feature itself is still intact for a genuinely critical finding."""
        config = EarlyTerminationConfig(enabled=True, min_confidence=0.9, max_agents_before_check=3)
        reports = [
            self.create_report("auth", 0.6, "medium"),
            self.create_report("business_logic", 0.5, "medium"),
            self.create_report("sqli", 0.95, "critical"),
        ]
        result = should_terminate_early(reports, ["idor", "xss"], config)
        self.assertTrue(result[0])


class TestFastPathSelector(unittest.TestCase):
    """Test the FastPathSelector class."""
    
    def setUp(self):
        """Set up test selector."""
        self.available = {"sqli", "xss", "idor", "ssrf", "auth", "business_logic", "misconfig"}
        self.selector = FastPathSelector(self.available)
    
    def test_fast_path_hit_tracking(self):
        """Fast-path hits should be tracked."""
        exchange = HttpExchange(
            url="https://example.com/graphql",
            method="POST",
            request_headers={},
            request_body="",
            response_status=200,
            response_headers={},
            response_body="",
        )
        
        self.selector.select_agents(exchange)
        
        stats = self.selector.get_stats()
        self.assertEqual(stats['fast_path_hits'], 1)
    
    def test_fast_path_miss_tracking(self):
        """Fast-path misses should be tracked."""
        exchange = HttpExchange(
            url="https://example.com/unknown",
            method="GET",
            request_headers={},
            request_body="",
            response_status=200,
            response_headers={},
            response_body="",
        )
        
        self.selector.select_agents(exchange)
        
        stats = self.selector.get_stats()
        self.assertEqual(stats['fast_path_misses'], 1)
    
    def test_early_termination_tracking(self):
        """Early terminations should be tracked."""
        from harness.models import AgentReport, Finding
        
        # Update config to allow early termination with 1 report
        self.selector.early_term_config = EarlyTerminationConfig(
            enabled=True,
            min_confidence=0.9,
            min_severity={"critical", "high"},
            max_agents_before_check=1,
        )
        
        report = AgentReport(
            agent="sqli",
            model="test",
            findings=[
                Finding(
                    vulnerability_class="sqli",
                    confidence=0.95,
                    severity="critical",
                    summary="Test",
                    evidence="test",
                    suggested_test="test",
                    basis="derived",
                )
            ],
        )
        self.selector.check_early_termination([report], ["xss", "idor"])
        stats = self.selector.get_stats()
        self.assertEqual(stats['early_terminations'], 1)
    def test_reset_stats(self):
        """Stats should be resettable."""
        exchange = HttpExchange(
            url="https://example.com/graphql",
            method="POST",
            request_headers={},
            request_body="",
            response_status=200,
            response_headers={},
            response_body="",
        )
        
        self.selector.select_agents(exchange)
        self.selector.reset_stats()
        
        stats = self.selector.get_stats()
        self.assertEqual(stats['fast_path_hits'], 0)


if __name__ == "__main__":
    unittest.main()
