"""Tests for deferred-leg validators: verb_tamper, csrf, file_upload."""
import asyncio
import unittest
from unittest.mock import AsyncMock, patch, MagicMock

from models import Finding, HttpExchange
from validators.verb_tamper_validator import VerbTamperValidator
from validators.csrf_validator import CsrfValidator, _has_csrf_token, _session_cookie_samesite
from validators.file_upload_validator import FileUploadValidator
from run_context import RunContext, ScopePolicy
from test_run_context import _Fixture


def _exchange(url="http://target.test/api/admin", method="GET", status=403,
              request_body="", request_headers=None, response_headers=None):
    return HttpExchange(
        url=url, method=method, response_status=status,
        request_headers=request_headers or {},
        response_headers=response_headers or {},
        request_body=request_body, response_body="",
    )


def _finding(vuln_class="misconfig"):
    return Finding(vulnerability_class=vuln_class, severity="medium", confidence=0.7,
                   summary="test", evidence="test", suggested_test="test", basis="derived")


# ---- VerbTamperValidator ----

class VerbTamperTests(unittest.TestCase):
    def setUp(self):
        self.v = VerbTamperValidator(allowed_hosts=["target.test"])

    def test_skip_2xx_original(self):
        ex = _exchange(status=200)
        r = asyncio.run(self.v.validate(_finding(), ex))
        self.assertEqual(r.status, "skipped")

    def test_skip_non_denial_status(self):
        ex = _exchange(status=500)
        r = asyncio.run(self.v.validate(_finding(), ex))
        self.assertEqual(r.status, "skipped")

    def test_skip_out_of_scope(self):
        ex = _exchange(url="http://evil.test/admin", status=403)
        r = asyncio.run(self.v.validate(_finding(), ex))
        self.assertEqual(r.status, "skipped")

    @patch("validators.verb_tamper_validator.GatedAsyncClient")
    @patch("global_throttle.acquire", new_callable=AsyncMock)
    def test_method_bypass_is_observation_not_confirmed(self, _throttle, mock_client_cls):
        # RETIRED (review 2026-09-09): an alternate method returning 2xx is an
        # observation, not a confirmed authz bypass (may be ordinary routing).
        ex = _exchange(method="POST", status=403)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"secret": "admin data"}'
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client_cls.return_value = mock_client
        r = asyncio.run(self.v.validate(_finding(), ex))
        self.assertEqual(r.status, "not_confirmed")
        self.assertFalse(r.confirmed)
        self.assertIn("observation", r.summary.lower())

    def test_mutating_methods_off_by_default(self):
        self.assertFalse(self.v.try_mutating_methods)

    @patch("validators.verb_tamper_validator.GatedAsyncClient")
    @patch("global_throttle.acquire", new_callable=AsyncMock)
    def test_mutating_bypass_is_observation_when_opted_in(self, _throttle, mock_client_cls):
        # V15: GET/POST denied but a mutating method (PUT/PATCH/DELETE) is open --
        # only tried under the explicit try_mutating_methods opt-in. RETIRED
        # (review 2026-09-09): this is an observation, not a confirmed bypass.
        from safety_gate import reset_default_gate, get_default_gate
        reset_default_gate()
        get_default_gate({"active_enabled": True, "allow_mutating_replay": True})
        v = VerbTamperValidator(allowed_hosts=["target.test"], try_mutating_methods=True)
        ex = _exchange(url="http://target.test/api/item/1", method="GET", status=403)
        # safe methods all deny (403), the first mutating method (PUT) succeeds
        def _req(method, url, **kw):
            r = MagicMock()
            if method in ("HEAD", "OPTIONS", "GET", "POST"):
                r.status_code = 403; r.text = "denied"
            else:  # PUT/PATCH/DELETE
                r.status_code = 200; r.text = "updated ok, substantial body here"
            return r
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=_req)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client_cls.return_value = mock_client
        r = asyncio.run(v.validate(_finding(), ex))
        reset_default_gate()
        self.assertEqual(r.status, "not_confirmed")
        self.assertFalse(r.confirmed)
        self.assertIn("mutating", r.summary.lower())

    @patch("validators.verb_tamper_validator.GatedAsyncClient")
    @patch("global_throttle.acquire", new_callable=AsyncMock)
    def test_not_confirmed_all_denied(self, _throttle, mock_client_cls):
        ex = _exchange(method="DELETE", status=401)
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client_cls.return_value = mock_client
        r = asyncio.run(self.v.validate(_finding(), ex))
        self.assertEqual(r.status, "not_confirmed")
        self.assertFalse(r.confirmed)


# ---- CsrfValidator ----

class CsrfHelperTests(unittest.TestCase):
    def test_has_csrf_token_in_body(self):
        ex = _exchange(request_body="csrf_token=abc123&name=test")
        self.assertTrue(_has_csrf_token(ex))

    def test_no_csrf_token(self):
        ex = _exchange(request_body="name=test&value=hello")
        self.assertFalse(_has_csrf_token(ex))

    def test_has_csrf_token_in_header(self):
        ex = _exchange(request_headers={"X-CSRF-Token": "abc123"})
        self.assertTrue(_has_csrf_token(ex))

    def test_samesite_strict(self):
        ex = _exchange(response_headers={"Set-Cookie": "session=abc; Path=/; SameSite=Strict"})
        self.assertEqual(_session_cookie_samesite(ex), "Strict")

    def test_samesite_lax(self):
        ex = _exchange(response_headers={"Set-Cookie": "sessionid=abc; SameSite=Lax"})
        self.assertEqual(_session_cookie_samesite(ex), "Lax")

    def test_samesite_none(self):
        ex = _exchange(response_headers={"Set-Cookie": "session=abc; SameSite=None"})
        self.assertEqual(_session_cookie_samesite(ex), "None")

    def test_no_samesite(self):
        ex = _exchange(response_headers={"Set-Cookie": "session=abc; Path=/"})
        self.assertIsNone(_session_cookie_samesite(ex))

    def test_no_session_cookie(self):
        ex = _exchange(response_headers={"Set-Cookie": "theme=dark; Path=/"})
        self.assertIsNone(_session_cookie_samesite(ex))


class CsrfValidatorTests(unittest.TestCase):
    def setUp(self):
        self.v = CsrfValidator(allowed_hosts=["target.test"])

    def test_applies_only_to_mutating_methods(self):
        f = _finding("csrf")
        self.assertTrue(self.v.applies(f, _exchange(method="POST")))
        self.assertFalse(self.v.applies(f, _exchange(method="GET")))

    def test_not_confirmed_samesite_strict(self):
        ex = _exchange(method="POST", status=200,
                       response_headers={"Set-Cookie": "session=abc; SameSite=Strict"})
        r = asyncio.run(self.v.validate(_finding("csrf"), ex))
        self.assertEqual(r.status, "not_confirmed")
        self.assertIn("SameSite", r.summary)

    @patch("validators.csrf_validator.GatedAsyncClient")
    @patch("global_throttle.acquire", new_callable=AsyncMock)
    def test_no_token_no_samesite_is_observation_not_confirmed(self, _throttle, mock_client_cls):
        # RETIRED (review 2026-09-09): a token-strip 2xx replay is an observation,
        # not confirmed CSRF (needs a cross-site browser PoC with ambient creds).
        ex = _exchange(method="POST", status=200, request_body="action=delete&id=1",
                       response_headers={"Set-Cookie": "session=abc; Path=/"})
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client_cls.return_value = mock_client
        r = asyncio.run(self.v.validate(_finding("csrf"), ex))
        self.assertEqual(r.status, "not_confirmed")
        self.assertFalse(r.confirmed)
        self.assertIn("observation", r.summary.lower())


class RunContextTransportTests(unittest.TestCase):
    def _context(self, fixture, *, budget=10):
        ctx = RunContext.create(
            allowed_hosts=["127.0.0.1"], max_requests=budget,
            gate_config={"active_enabled": True, "allow_mutating_replay": True})
        ctx.sessions.register(
            "victim", "victim", {"Authorization": "Bearer victim"},
            allowed_origins=[ScopePolicy.origin_of(fixture.base)], role="user")
        return ctx

    def test_csrf_replay_uses_run_session_and_shared_budget(self):
        fixture = _Fixture()
        ctx = self._context(fixture, budget=1)
        validator = CsrfValidator(allowed_hosts=["127.0.0.1"], run_context=ctx)
        exchange = _exchange(
            url=fixture.base + "/csrf", method="POST", status=200,
            request_headers={"Authorization": "Bearer victim", "X-CSRF-Token": "secret"},
            request_body="action=update&csrf_token=secret")
        async def scenario():
            result = await validator.validate(_finding("csrf"), exchange)
            await ctx.aclose()
            return result
        try:
            result = asyncio.run(scenario())
            self.assertEqual(result.status, "not_confirmed")
            self.assertEqual(ctx.budget.used, 1)
            self.assertEqual(fixture.httpd.received[0]["authorization"], "Bearer victim")
            self.assertNotIn("csrf", fixture.httpd.received[0]["body"].lower())
        finally:
            fixture.close()

    def test_csrf_unknown_credentials_fail_closed_without_send(self):
        fixture = _Fixture()
        ctx = self._context(fixture)
        validator = CsrfValidator(allowed_hosts=["127.0.0.1"], run_context=ctx)
        exchange = _exchange(
            url=fixture.base + "/csrf", method="POST", status=200,
            request_headers={"Authorization": "Bearer unregistered"},
            request_body="action=update")
        async def scenario():
            result = await validator.validate(_finding("csrf"), exchange)
            await ctx.aclose()
            return result
        try:
            result = asyncio.run(scenario())
            self.assertEqual(result.status, "skipped")
            self.assertEqual(fixture.httpd.received, [])
            self.assertEqual(ctx.budget.used, 0)
        finally:
            fixture.close()

    def test_verb_tamper_uses_run_session_for_actual_alternate(self):
        fixture = _Fixture()
        ctx = self._context(fixture)
        validator = VerbTamperValidator(allowed_hosts=["127.0.0.1"], run_context=ctx)
        exchange = _exchange(
            url=fixture.base + "/admin", method="POST", status=403,
            request_headers={"Authorization": "Bearer victim"})
        async def scenario():
            result = await validator.validate(_finding(), exchange)
            await ctx.aclose()
            return result
        try:
            result = asyncio.run(scenario())
            self.assertEqual(result.status, "not_confirmed")
            self.assertIn("observation", result.summary.lower())
            self.assertEqual(fixture.httpd.received[-1]["authorization"], "Bearer victim")
            self.assertGreaterEqual(ctx.budget.used, 1)
        finally:
            fixture.close()

    @patch("validators.csrf_validator.GatedAsyncClient")
    @patch("global_throttle.acquire", new_callable=AsyncMock)
    def test_not_confirmed_replay_rejected(self, _throttle, mock_client_cls):
        ex = _exchange(method="POST", status=200, request_body="action=delete",
                       response_headers={"Set-Cookie": "session=abc; Path=/"})
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client_cls.return_value = mock_client
        r = asyncio.run(CsrfValidator(allowed_hosts=["target.test"]).validate(
            _finding("csrf"), ex))
        self.assertEqual(r.status, "not_confirmed")
        self.assertFalse(r.confirmed)


# ---- FileUploadValidator ----

class FileUploadTests(unittest.TestCase):
    def setUp(self):
        self.v = FileUploadValidator(allowed_hosts=["target.test"])

    def test_applies_post(self):
        f = _finding("file_upload")
        self.assertTrue(self.v.applies(f, _exchange(method="POST")))

    def test_not_applies_get(self):
        f = _finding("file_upload")
        self.assertFalse(self.v.applies(f, _exchange(method="GET")))

    def test_skip_out_of_scope(self):
        ex = _exchange(url="http://evil.test/upload", method="POST", status=200)
        r = asyncio.run(self.v.validate(_finding("file_upload"), ex))
        self.assertEqual(r.status, "skipped")

    @patch("validators.file_upload_validator.GatedAsyncClient")
    @patch("global_throttle.acquire", new_callable=AsyncMock)
    def test_not_confirmed_upload_rejected(self, _throttle, mock_client_cls):
        ex = _exchange(url="http://target.test/api/upload", method="POST", status=200)
        mock_resp = MagicMock()
        mock_resp.status_code = 415
        mock_client = AsyncMock()
        # GatedAsyncClient exposes only .request() (R04) -- mock that, not .post().
        mock_client.request = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client_cls.return_value = mock_client
        r = asyncio.run(self.v.validate(_finding("file_upload"), ex))
        self.assertEqual(r.status, "not_confirmed")

    @patch("validators.file_upload_validator.GatedAsyncClient")
    @patch("global_throttle.acquire", new_callable=AsyncMock)
    def test_confirmed_html_stored_and_served(self, _throttle, mock_client_cls):
        ex = _exchange(url="http://target.test/api/upload", method="POST", status=200)
        upload_resp = MagicMock()
        upload_resp.status_code = 200
        upload_resp.text = ""
        upload_resp.json = lambda: {"url": "/uploads/test-abc.html"}

        retrieve_resp = MagicMock()
        retrieve_resp.status_code = 200
        retrieve_resp.text = "<!-- harness-upload-"  # will be checked for marker
        retrieve_resp.headers = {"content-type": "text/html"}

        mock_client = AsyncMock()

        # GatedAsyncClient exposes only .request(method, url, ...) (R04): dispatch
        # on the method rather than mocking .post()/.get() (which never existed).
        async def _request(method, url, *args, **kwargs):
            return retrieve_resp if method.upper() == "GET" else upload_resp

        mock_client.request = _request
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client_cls.return_value = mock_client

        # Patch the nonce to make marker predictable
        import validators.file_upload_validator as fu_mod
        orig_token_hex = None
        nonce = "deadbeef01234567"

        with patch("secrets.token_hex", return_value=nonce):
            marker = f"<!-- harness-upload-{nonce} -->"
            retrieve_resp.text = marker
            r = asyncio.run(self.v.validate(_finding("file_upload"), ex))

        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)


class RealWrapperFileUploadTests(unittest.TestCase):
    """R04 regression guard: exercise the REAL GatedAsyncClient (which exposes
    ONLY .request(), not .post()/.get()) against an in-process httpx.MockTransport.
    The previous mocked tests used an unrestricted AsyncMock that silently
    provided .post()/.get(), so they never caught the AttributeError that fired
    before any upload request was sent. This test uses the real wrapper + gate."""

    def setUp(self):
        import safety_gate
        safety_gate.reset_default_gate()
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True})
        self.v = FileUploadValidator(allowed_hosts=["target.test"])

    def tearDown(self):
        import safety_gate
        safety_gate.reset_default_gate()

    def _validate_with(self, handler):
        import httpx
        import validators.file_upload_validator as fu_mod
        real_cls = fu_mod.GatedAsyncClient

        def _factory(gate, name, **kw):
            kw.pop("verify", None)  # custom transport supersedes verify
            kw["transport"] = httpx.MockTransport(handler)
            return real_cls(gate, name, **kw)

        ex = _exchange(url="http://target.test/api/upload", method="POST", status=200)
        with patch.object(fu_mod, "GatedAsyncClient", _factory), \
                patch("global_throttle.acquire", new_callable=AsyncMock):
            return asyncio.run(self.v.validate(_finding("file_upload"), ex))

    def test_confirmed_through_real_gated_wrapper(self):
        import re
        import httpx
        stored = {}

        def handler(request):
            if request.method == "POST":
                body = request.content.decode(errors="ignore")
                m = re.search(r"harness-upload-([0-9a-f]+)", body)
                token = m.group(1) if m else "x"
                stored["marker"] = f"<!-- harness-upload-{token} -->"
                return httpx.Response(200, json={"url": f"/uploads/test-{token}.html"})
            return httpx.Response(200, text=stored.get("marker", ""),
                                  headers={"content-type": "text/html"})

        r = self._validate_with(handler)
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)

    def test_rejected_upload_is_negative_control(self):
        import httpx

        def handler(request):
            return httpx.Response(415, text="unsupported media type")

        r = self._validate_with(handler)
        self.assertEqual(r.status, "not_confirmed")

    def test_blocked_when_mutating_not_authorized(self):
        # With mutating replay OFF, the gate must block the POST -> skipped, not crash.
        import safety_gate, httpx
        safety_gate.reset_default_gate()
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": False})

        def handler(request):  # should never be reached
            return httpx.Response(200, json={"url": "/uploads/x.html"})

        r = self._validate_with(handler)
        self.assertEqual(r.status, "skipped")


# ---- Negative controls ----

class NegativeControlTests(unittest.TestCase):
    """New legs must never invent findings from benign inputs."""

    def test_verb_tamper_no_finding_on_2xx(self):
        v = VerbTamperValidator(allowed_hosts=["target.test"])
        ex = _exchange(status=200)
        r = asyncio.run(v.validate(_finding(), ex))
        self.assertFalse(r.confirmed)

    def test_csrf_no_finding_with_samesite_lax(self):
        v = CsrfValidator(allowed_hosts=["target.test"])
        ex = _exchange(method="POST", status=200,
                       response_headers={"Set-Cookie": "session=abc; SameSite=Lax"})
        r = asyncio.run(v.validate(_finding("csrf"), ex))
        self.assertFalse(r.confirmed)

    def test_file_upload_no_finding_on_get(self):
        v = FileUploadValidator(allowed_hosts=["target.test"])
        f = _finding("file_upload")
        ex = _exchange(method="GET")
        self.assertFalse(v.applies(f, ex))


# ---- Registry integration ----

class RegistryTests(unittest.TestCase):
    def test_new_validators_registered(self):
        from validators.registry import ValidatorRegistry
        reg = ValidatorRegistry({"validators": {"active_enabled": True}})
        self.assertIn("verb_tamper", reg.validators)
        self.assertIn("csrf", reg.validators)
        self.assertIn("file_upload", reg.validators)

    def test_new_validators_active(self):
        from validators.registry import ValidatorRegistry
        reg = ValidatorRegistry({"validators": {"active_enabled": True}})
        self.assertTrue(reg.validators["verb_tamper"].active)
        self.assertTrue(reg.validators["csrf"].active)
        self.assertTrue(reg.validators["file_upload"].active)


if __name__ == "__main__":
    unittest.main()
