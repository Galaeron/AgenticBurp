"""Tests for the authenticated-role login helper in the web-objective smoke
runner. The pure form-parsing/credential-mapping step is tested directly so the
authenticated-surface wiring (login-gated labs: IDOR, JWT, 2FA, uploads) has a
caller-independent regression, including CSRF-token preservation.

Also covers LB-3: a bounded cold-login retry/warmup in ``_authenticate`` (a
freshly-launched instance can intermittently drop the very first request), and
the ``_auth_info`` degraded marker that stops a dropped authenticated role
from silently passing a run off as anonymous."""
from __future__ import annotations

import unittest
from unittest import mock

import httpx

from testing.run_web_objective_smoke import (
    _auth_info,
    _authenticate,
    _login_form_data,
    _login_uses_json,
)


# A PortSwigger-style login page: a hidden CSRF token plus username/password.
_LOGIN_HTML = """
<html><body><form class="login-form" method="POST" action="/login">
  <input required type="hidden" name="csrf" value="Xy9CsRf0k3n">
  <label>Username</label><input required type="text" name="username" />
  <label>Password</label><input required type="password" name="password" />
  <button class="button" type="submit">Log in</button>
</form></body></html>
"""


class LoginFormDataTests(unittest.TestCase):
    def test_detects_javascript_json_login_submission(self):
        self.assertTrue(_login_uses_json(
            '<form><button onclick="event.preventDefault(); jsonSubmit(\'/login\')">Login</button></form>'))
        self.assertFalse(_login_uses_json(_LOGIN_HTML))
    def test_fills_credentials_and_preserves_csrf(self):
        action, method, data = _login_form_data(
            _LOGIN_HTML, "https://lab.example/login", "wiener", "peter")
        self.assertEqual(method, "POST")
        self.assertTrue(action.endswith("/login"), action)
        # CSRF token kept at its server value; creds filled by field name.
        self.assertEqual(data, {"csrf": "Xy9CsRf0k3n",
                                "username": "wiener", "password": "peter"})

    def test_maps_email_named_username_field(self):
        html = ('<form method="post" action="/session">'
                '<input name="email" type="email">'
                '<input name="password" type="password"></form>')
        _action, _method, data = _login_form_data(html, "https://x/login", "u@x", "pw")
        self.assertEqual(data["email"], "u@x")
        self.assertEqual(data["password"], "pw")

    def test_no_password_form_falls_back_to_bare_credentials(self):
        # A page with only a search box: no password form -> action None so the
        # caller posts bare credentials to the login path.
        html = '<form action="/search" method="get"><input name="q"></form>'
        action, method, data = _login_form_data(html, "https://x/login", "wiener", "peter")
        self.assertIsNone(action)
        self.assertEqual(method, "POST")
        self.assertEqual(data, {"username": "wiener", "password": "peter"})

    def test_selects_password_form_among_several(self):
        # A newsletter form precedes the real login form; the password one wins.
        html = ('<form action="/subscribe" method="post"><input name="email"></form>'
                '<form action="/login" method="post">'
                '<input type="hidden" name="csrf" value="TOK">'
                '<input name="username"><input name="password" type="password"></form>')
        action, _method, data = _login_form_data(html, "https://x/login", "wiener", "peter")
        self.assertTrue(action.endswith("/login"))
        self.assertEqual(data.get("csrf"), "TOK")
        self.assertEqual(data.get("password"), "peter")


_OK_LOGIN_HTML = """
<html><body><form method="POST" action="/account">
  <input type="hidden" name="csrf" value="TOK">
  <input name="username" type="text">
  <input name="password" type="password">
</form></body></html>
"""


def _mock_transport(get_fail_count: int, post_fail_count: int = 0,
                    get_fail_as: str = "error", post_fail_as: str = "error"):
    """Build an httpx.MockTransport whose handler fails the first N GETs (and/or
    POSTs) then succeeds, so _authenticate's retry loop can be exercised without
    any real sockets. 'error' raises a ConnectError; otherwise a 503 is
    returned (both are the transient failures the retry loop must absorb)."""
    calls = {"get": 0, "post": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            calls["get"] += 1
            if calls["get"] <= get_fail_count:
                if get_fail_as == "error":
                    raise httpx.ConnectError("cold instance refused connection",
                                             request=request)
                return httpx.Response(503, text="warming up")
            return httpx.Response(200, text=_OK_LOGIN_HTML,
                                  headers={"set-cookie": "session=abc123; Path=/"})
        calls["post"] += 1
        if calls["post"] <= post_fail_count:
            if post_fail_as == "error":
                raise httpx.ConnectError("cold instance refused connection",
                                         request=request)
            return httpx.Response(503, text="warming up")
        return httpx.Response(200, text="welcome",
                              headers={"set-cookie": "session=abc123; Path=/"})

    return httpx.MockTransport(handler), calls


class AuthenticateRetryTests(unittest.IsolatedAsyncioTestCase):
    """LB-3: a transport that fails the first GET then succeeds proves
    _authenticate retries and ultimately returns ok=True."""

    async def test_retries_cold_first_get_then_succeeds(self):
        transport, calls = _mock_transport(get_fail_count=1)
        with mock.patch("asyncio.sleep", mock.AsyncMock()):
            cookie, status, ok, seed = await _authenticate(
                "https://lab.example", "/login", "wiener", "peter",
                timeout=5.0, transport=transport)
        self.assertTrue(ok)
        self.assertNotEqual(status, 0)
        self.assertIn("session=abc123", cookie)
        self.assertIsNotNone(seed)
        # First GET failed and was retried: the handler saw 2 GET calls.
        self.assertEqual(calls["get"], 2)

    async def test_retries_cold_first_get_5xx_then_succeeds(self):
        transport, calls = _mock_transport(get_fail_count=1, get_fail_as="status")
        with mock.patch("asyncio.sleep", mock.AsyncMock()):
            cookie, status, ok, seed = await _authenticate(
                "https://lab.example", "/login", "wiener", "peter",
                timeout=5.0, transport=transport)
        self.assertTrue(ok)
        self.assertIn("session=abc123", cookie)
        self.assertEqual(calls["get"], 2)

    async def test_happy_path_first_attempt_unchanged(self):
        # No injected failures: exactly one GET and one POST, proving the
        # retry loop adds no overhead/behavior change when the first
        # attempt already works.
        transport, calls = _mock_transport(get_fail_count=0, post_fail_count=0)
        with mock.patch("asyncio.sleep", mock.AsyncMock()) as sleep_mock:
            cookie, status, ok, seed = await _authenticate(
                "https://lab.example", "/login", "wiener", "peter",
                timeout=5.0, transport=transport)
        self.assertTrue(ok)
        self.assertEqual(calls["get"], 1)
        self.assertEqual(calls["post"], 1)
        sleep_mock.assert_not_called()

    async def test_retry_gives_up_after_cap_exhausted(self):
        # Every attempt fails (more failures than the retry cap allows) ->
        # _authenticate must give up and return the early-fail tuple, proving
        # the retry is bounded rather than unbounded.
        transport, calls = _mock_transport(get_fail_count=99)
        with mock.patch("asyncio.sleep", mock.AsyncMock()):
            cookie, status, ok, seed = await _authenticate(
                "https://lab.example", "/login", "wiener", "peter",
                timeout=5.0, transport=transport)
        self.assertFalse(ok)
        self.assertEqual(cookie, "")
        self.assertEqual(status, 0)
        self.assertIsNone(seed)
        # Bounded: the handler was not called an unbounded number of times.
        self.assertLessEqual(calls["get"], 5)


class AuthInfoDegradedTests(unittest.TestCase):
    """LB-3: auth REQUESTED but never established must be marked degraded
    (fail-loud) in the artifact's auth block, with negative controls proving
    an established or a never-requested run is NOT marked degraded."""

    def test_requested_but_not_established_is_degraded(self):
        info = _auth_info(requested=True, ok=False, login_status=0, cookie="")
        self.assertTrue(info.get("degraded") is True)
        self.assertEqual(info.get("hard_error"),
                         "authentication requested but not established")

    def test_negative_control_requested_and_established_not_degraded(self):
        info = _auth_info(requested=True, ok=True, login_status=200,
                          cookie="session=abc123")
        self.assertNotIn("degraded", info)
        self.assertNotIn("hard_error", info)

    def test_negative_control_not_requested_not_degraded(self):
        # An anonymous run that never requested auth must never be flagged
        # degraded just because it has no session.
        info = _auth_info(requested=False, ok=False, login_status=0, cookie="")
        self.assertNotIn("degraded", info)
        self.assertNotIn("hard_error", info)


if __name__ == "__main__":
    unittest.main()
