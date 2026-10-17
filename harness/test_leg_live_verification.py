"""Leg integration against an owned loopback Flask fixture and collaborator.

Real HTTP plus vulnerable/secure controls exercise the confirmation adapters.
Browser cases require Playwright/Chromium; shell callback cases require curl.
Skipped cases establish no evidence. This is fixture integration, not a current
blind-target measurement; path traversal has a separate operator-driven fixture.
"""
import asyncio
import importlib.util
import shutil
import threading
import time
import unittest
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from werkzeug.serving import make_server

from harness import global_throttle
from harness import safety_gate
from harness.models import Finding, HttpExchange
from harness.validators.ssti_validator import SstiValidator
from harness.validators.open_redirect_validator import OpenRedirectValidator
from harness.validators.ssrf_validator import SsrfValidator
from harness.validators.sequence_validator import SequenceValidator
from harness.validators.command_injection_validator import CommandInjectionValidator
from harness.validators.deserialization_oob_validator import DeserializationOobValidator
from harness.validators.auth_sequence_validator import AuthSequenceValidator
from harness.validators.stored_xss_validator import StoredXssValidator
from harness.validators.jwt_forge_validator import JwtForgeValidator
from harness.validators.file_upload_validator import FileUploadValidator
from harness.validators.client_trust_validator import ClientTrustValidator
from harness.validators.browser_xss_validator import BrowserXssValidator
from harness.validators.xxe_validator import XxeValidator
from harness.validators.csrf_validator import CsrfValidator
from harness import browser_driver
from harness import driver_capture

_FIXTURE = (Path(__file__).resolve().parent.parent
            / "testing" / "leg-verification" / "vuln_fixture.py")


def _load_make_app():
    spec = importlib.util.spec_from_file_location("vuln_fixture", _FIXTURE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.make_app


def _finding(vc):
    return Finding(vulnerability_class=vc, confidence=0.5, severity="high",
                   summary=f"{vc} hypothesis", evidence="", suggested_test="", basis="derived")


class _RequestCounter:
    """WSGI middleware that counts every request the fixture actually serves.

    Rule 4 (a test must prove it exercised something): a leg that claims a
    verdict without a request having reached the fixture would be vacuous
    evidence -- exactly the silent-hollowing failure mode a scope/auth change
    could reintroduce. Each positive/negative-control leg asserts this counter
    advanced during validate(); the one passive-discovery leg (meant to send
    nothing) asserts it did not.

    This also supplies the exact-PORT evidence the gate scope cannot express:
    the fixture binds exactly one ephemeral port, so a counted request is proof
    the leg reached THIS fixture on THAT exact port. The production gate scope is
    deliberately exact-host-only and port-agnostic -- scope_lock.parse_scope_entry
    rejects any port-bearing entry (W-17), so '127.0.0.1:<port>' cannot be
    configured there without exercising a non-production parse path.
    """

    def __init__(self, app):
        self._app = app
        self.count = 0

    def __call__(self, environ, start_response):
        self.count += 1  # incremented in the werkzeug serving thread; read after
        return self._app(environ, start_response)  # the validate() call settles


class LiveLegVerificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import logging
        logging.getLogger("werkzeug").setLevel(logging.ERROR)  # quiet per-request logs
        global_throttle.configure(0)
        app = _load_make_app()()
        cls._counter = _RequestCounter(app)  # Rule 4: prove each leg reached the fixture
        cls._server = make_server("127.0.0.1", 0, cls._counter, threaded=True)
        cls._port = cls._server.server_address[1]
        cls._thread = threading.Thread(target=cls._server.serve_forever, daemon=True)
        cls._thread.start()
        cls._base = f"http://127.0.0.1:{cls._port}"
        # Wait until the server actually answers before running any leg.
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                urllib.request.urlopen(f"{cls._base}/health", timeout=0.5).read()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("leg-verification fixture did not come up")
        safety_gate.reset_default_gate()
        # Seed the gate's SCOPE too, not just the mode flags: the scope lock
        # (3c622c3) fails closed on an empty active scope, so without the
        # fixture host here every mutating leg is refused at authorize() and
        # skips ("not authorized") before it can confirm. The per-validator
        # allowed_hosts is a separate check and does not arm the gate.
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True,
                                      "allowed_hosts": ["127.0.0.1"]})

    @classmethod
    def tearDownClass(cls):
        cls._server.shutdown()
        cls._thread.join(timeout=5.0)
        safety_gate.reset_default_gate()

    @classmethod
    def _sent_count(cls):
        return cls._counter.count

    def _check_sent(self, before, expect_sent, res):
        """Rule 4: a leg's verdict is only real evidence if it sent traffic the
        fixture actually served. Assert the exact direction every time."""
        sent = self._sent_count() - before
        if expect_sent:
            self.assertGreater(
                sent, 0,
                f"leg reported {getattr(res, 'status', '?')!r} without any request "
                f"reaching the fixture -- the live evidence would be vacuous")
        else:
            self.assertEqual(
                sent, 0,
                f"a send-nothing leg unexpectedly issued {sent} request(s) to the fixture")

    def _run(self, validator, path, *, expect_sent=True):
        ex = HttpExchange(url=f"{self._base}{path}", method="GET",
                          request_headers={}, request_body="")
        fc = next(iter(validator.finding_classes))
        before = self._sent_count()
        res = asyncio.run(validator.validate(_finding(fc), ex))
        self._check_sent(before, expect_sent, res)
        return res

    def _run_ex(self, validator, exchange, fc, *, expect_sent=True):
        before = self._sent_count()
        res = asyncio.run(validator.validate(_finding(fc), exchange))
        self._check_sent(before, expect_sent, res)
        return res

    def _reset_profiles(self):
        urllib.request.urlopen(urllib.request.Request(
            f"{self._base}/account/reset", method="POST"), timeout=2).read()

    # --- SSTI -----------------------------------------------------------------
    def test_ssti_confirms_on_real_template_render(self):
        v = SstiValidator(allowed_hosts=["127.0.0.1"])
        res = self._run(v, "/ssti/render?q=seed")
        self.assertEqual(res.status, "confirmed",
                         f"SSTI leg did not confirm against a real Jinja render endpoint: {res.summary}")
        self.assertTrue(res.confirmed)

    def test_ssti_silent_on_escaped_echo_control(self):
        v = SstiValidator(allowed_hosts=["127.0.0.1"])
        res = self._run(v, "/ssti/echo?q=seed")
        self.assertNotEqual(res.status, "confirmed")

    # --- Open redirect --------------------------------------------------------
    def test_open_redirect_confirms_on_blind_redirect(self):
        v = OpenRedirectValidator(allowed_hosts=["127.0.0.1"])
        res = self._run(v, "/redirect/open?url=/seed")
        self.assertEqual(res.status, "confirmed",
                         f"open-redirect leg did not confirm against a real blind redirect: {res.summary}")
        self.assertTrue(res.confirmed)

    def test_open_redirect_silent_on_fixed_target_control(self):
        v = OpenRedirectValidator(allowed_hosts=["127.0.0.1"])
        res = self._run(v, "/redirect/safe?url=/seed")
        self.assertNotEqual(res.status, "confirmed")

    # --- SSRF (OOB via the real in-process collaborator) ----------------------
    def test_ssrf_confirms_on_real_server_side_fetch(self):
        v = SsrfValidator(allowed_hosts=["127.0.0.1"], timeout=1.0)
        res = self._run(v, "/ssrf/fetch?url=http://example.invalid/x")
        self.assertEqual(res.status, "confirmed",
                         f"SSRF leg did not confirm against a real server-side fetch: {res.summary}")
        self.assertTrue(res.confirmed)

    def test_ssrf_silent_on_no_fetch_control(self):
        v = SsrfValidator(allowed_hosts=["127.0.0.1"], timeout=1.0)
        res = self._run(v, "/ssrf/safe?url=http://example.invalid/x")
        self.assertNotEqual(res.status, "confirmed")

    # --- Sequence / mass assignment (write -> re-read differential) -----------
    def _profile_exchange(self, path):
        return HttpExchange(url=f"{self._base}{path}", method="PATCH",
                            request_headers={"Content-Type": "application/json"},
                            request_body='{"name": "alice"}')

    def test_sequence_confirms_on_mass_assignable_write(self):
        self._reset_profiles()
        v = SequenceValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._profile_exchange("/account/profile"), "mass_assignment")
        self.assertEqual(res.status, "confirmed",
                         f"sequence leg did not confirm a real mass-assignable write: {res.summary}")
        self.assertTrue(res.confirmed)

    def test_sequence_silent_on_allowlisted_control(self):
        self._reset_profiles()
        v = SequenceValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._profile_exchange("/account/profile-safe"), "mass_assignment")
        self.assertNotEqual(res.status, "confirmed")

    def test_sequence_confirms_nested_response_and_noncanonical_field(self):
        # The generalised leg must catch a mass-assign the ORIGINAL leg missed:
        # the escalation field (is_premium) is outside the canonical set AND the
        # response nests the object under wrapper keys. Requires both the
        # authority-named schema-derived candidate AND the recursive detection.
        self._reset_profiles()
        v = SequenceValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._profile_exchange("/account/tier"), "mass_assignment")
        self.assertEqual(res.status, "confirmed",
                         f"sequence leg missed a nested/non-canonical mass-assign: {res.summary}")
        self.assertTrue(res.confirmed)

    def test_sequence_silent_on_nested_allowlisted_control(self):
        self._reset_profiles()
        v = SequenceValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._profile_exchange("/account/tier-safe"), "mass_assignment")
        self.assertNotEqual(res.status, "confirmed")

    def test_sequence_confirms_privilege_escalation_class(self):
        # V18: the sequence leg's mechanism (inject role=admin/is_admin, re-read
        # shows it persisted) IS privilege escalation. Prove it confirms when the
        # finding is labelled privilege_escalation, so promoting that class to
        # LIVE_VERIFIED is honest (same live-verified write->re-read differential).
        self._reset_profiles()
        v = SequenceValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._profile_exchange("/account/profile"), "privilege_escalation")
        self.assertEqual(res.status, "confirmed",
                         f"sequence leg did not confirm a privilege_escalation-classed write: {res.summary}")
        self.assertTrue(res.confirmed)

    def test_sequence_confirms_form_encoded_mass_assign(self):
        # V14 no-bite fix: a form-encoded (not JSON) mass-assignable write must
        # also be caught -- VulnCorp's profile updates are form-encoded.
        self._reset_profiles()
        v = SequenceValidator(allowed_hosts=["127.0.0.1"])
        ex = HttpExchange(url=f"{self._base}/account/profile", method="PATCH",
                          request_headers={"Content-Type": "application/x-www-form-urlencoded"},
                          request_body="name=alice")
        res = self._run_ex(v, ex, "mass_assignment")
        self.assertEqual(res.status, "confirmed",
                         f"sequence leg did not confirm a form-encoded mass-assign: {res.summary}")
        self.assertTrue(res.confirmed)

    # --- Command injection (OOB shell fetch; needs curl on the target) --------
    @unittest.skipIf(shutil.which("curl") is None, "curl not available to exercise the shell payload")
    def test_command_injection_confirms_via_shell(self):
        v = CommandInjectionValidator(allowed_hosts=["127.0.0.1"], timeout=1.0)
        res = self._run(v, "/cmdi/ping?host=seed")
        self.assertEqual(res.status, "confirmed",
                         f"command-injection leg did not confirm against a real shell endpoint: {res.summary}")
        self.assertTrue(res.confirmed)

    def test_command_injection_silent_on_no_shell_control(self):
        v = CommandInjectionValidator(allowed_hosts=["127.0.0.1"], timeout=1.0)
        res = self._run(v, "/cmdi/safe?host=seed")
        self.assertNotEqual(res.status, "confirmed")

    # --- Active deserialization (pickle OOB beacon) ---------------------------
    def _pickle_cookie_exchange(self, path):
        import base64 as _b64, pickle as _pk
        seed = _b64.b64encode(_pk.dumps({"user": "alice"})).decode()  # benign pickle-shaped cookie
        return HttpExchange(url=f"{self._base}{path}", method="GET",
                            request_headers={"Cookie": f"session={seed}"}, request_body="")

    def test_deserialization_oob_confirms_on_pickle_sink(self):
        v = DeserializationOobValidator(allowed_hosts=["127.0.0.1"], timeout=2.0)
        res = self._run_ex(v, self._pickle_cookie_exchange("/deser/load"), "deserialization")
        self.assertEqual(res.status, "confirmed",
                         f"deserialization leg did not confirm a real pickle.loads sink: {res.summary}")
        self.assertTrue(res.confirmed)

    def test_deserialization_oob_silent_on_json_control(self):
        v = DeserializationOobValidator(allowed_hosts=["127.0.0.1"], timeout=2.0)
        res = self._run_ex(v, self._pickle_cookie_exchange("/deser/safe"), "deserialization")
        self.assertNotEqual(res.status, "confirmed")

    # --- Auth-mechanism legs (session fixation / weak pw / username enum) -----
    def _auth_exchange(self, path, body):
        return HttpExchange(url=f"{self._base}{path}", method="POST",
                            request_headers={"Content-Type": "application/json"},
                            request_body=body)

    def test_auth_session_fixation_confirms(self):
        v = AuthSequenceValidator(allowed_hosts=["127.0.0.1"])
        ex = self._auth_exchange("/auth/login-fixation", '{"username": "alice", "password": "x"}')
        res = self._run_ex(v, ex, "session_fixation")
        self.assertEqual(res.status, "confirmed", f"session-fixation leg missed a non-rotating session: {res.summary}")

    def test_auth_session_fixation_silent_on_rotating_control(self):
        v = AuthSequenceValidator(allowed_hosts=["127.0.0.1"])
        ex = self._auth_exchange("/auth/login-rotate", '{"username": "alice", "password": "x"}')
        res = self._run_ex(v, ex, "session_fixation")
        self.assertNotEqual(res.status, "confirmed")

    def test_auth_weak_password_confirms(self):
        v = AuthSequenceValidator(allowed_hosts=["127.0.0.1"])
        ex = self._auth_exchange("/auth/register-weak", '{"username": "alice", "password": "alicepw123"}')
        res = self._run_ex(v, ex, "weak_password")
        self.assertEqual(res.status, "confirmed", f"weak-password leg missed an unrestricted policy: {res.summary}")

    def test_auth_weak_password_silent_on_policy_control(self):
        v = AuthSequenceValidator(allowed_hosts=["127.0.0.1"])
        ex = self._auth_exchange("/auth/register-strong", '{"username": "alice", "password": "alicepw123"}')
        res = self._run_ex(v, ex, "weak_password")
        self.assertNotEqual(res.status, "confirmed")

    def test_auth_username_enum_confirms(self):
        v = AuthSequenceValidator(allowed_hosts=["127.0.0.1"])
        ex = self._auth_exchange("/auth/login-enum", '{"username": "alice", "password": "alicepw"}')
        res = self._run_ex(v, ex, "username_enumeration")
        self.assertEqual(res.status, "confirmed", f"username-enum leg missed a discriminating response: {res.summary}")

    def test_auth_username_enum_silent_on_uniform_control(self):
        v = AuthSequenceValidator(allowed_hosts=["127.0.0.1"])
        ex = self._auth_exchange("/auth/login-uniform", '{"username": "alice", "password": "alicepw"}')
        res = self._run_ex(v, ex, "username_enumeration")
        self.assertNotEqual(res.status, "confirmed")

    def test_auth_2fa_bypass_confirms(self):
        # Step-1 login lands on a 2nd-factor step, yet the protected account page is
        # reachable with that partial session (and denied with none) -> MFA bypass.
        v = AuthSequenceValidator(allowed_hosts=["127.0.0.1"])
        ex = self._auth_exchange("/2fa/login", '{"username": "alice", "password": "alicepw"}')
        res = self._run_ex(v, ex, "2fa_bypass")
        self.assertEqual(res.status, "confirmed",
                         f"2FA-bypass leg missed a step-1-only session reaching the account: {res.summary}")
        self.assertTrue(res.confirmed)

    def test_auth_2fa_bypass_silent_on_enforcing_control(self):
        # NEGATIVE CONTROL: identical flow, but the account page enforces the 2nd
        # factor (redirects a partial session back to /2fa/verify) -> must NOT confirm.
        v = AuthSequenceValidator(allowed_hosts=["127.0.0.1"])
        ex = self._auth_exchange("/2fa/login-safe", '{"username": "alice", "password": "alicepw"}')
        res = self._run_ex(v, ex, "2fa_bypass")
        self.assertNotEqual(res.status, "confirmed")

    # --- Stored / second-order XSS (plant -> independent HTML render) ---------
    def _stored_reset(self):
        urllib.request.urlopen(urllib.request.Request(
            f"{self._base}/stored/reset", method="POST"), timeout=2).read()

    def _comment_exchange(self, path):
        return HttpExchange(url=f"{self._base}{path}", method="POST",
                            request_headers={"Content-Type": "application/json"},
                            request_body='{"text": "hello world"}')

    def test_stored_xss_confirms_on_raw_render(self):
        self._stored_reset()
        v = StoredXssValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._comment_exchange("/stored/comments"), "xss")
        self.assertEqual(res.status, "confirmed",
                         f"stored-XSS leg missed a plant->raw-render flow: {res.summary}")
        self.assertTrue(res.confirmed)

    def test_stored_xss_silent_on_escaped_render_control(self):
        self._stored_reset()
        v = StoredXssValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._comment_exchange("/stored/comments-safe"), "xss")
        self.assertNotEqual(res.status, "confirmed")

    # --- Stored XSS via a CSRF-token-bound comment FORM (PortSwigger-shaped) ---
    def _blog_reset(self):
        urllib.request.urlopen(urllib.request.Request(
            f"{self._base}/blog/reset", method="POST"), timeout=2).read()

    def _blog_comment_exchange(self, path):
        # A urlencoded comment write whose captured csrf token is STALE (bound to
        # the crawl's session, not the validator's). The leg must mint a fresh
        # token from the source page; reusing this stale one yields 400 and stores
        # nothing, so a pass proves the in-session token refresh actually works.
        return HttpExchange(
            url=f"{self._base}{path}", method="POST",
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            request_body=("csrf=STALE-CAPTURED-TOKEN&postId=1&comment=seed"
                          "&name=probe&email=probe%40example.com&website=http%3A%2F%2Fexample.com%2F"))

    def test_stored_xss_confirms_through_csrf_bound_form(self):
        self._blog_reset()
        v = StoredXssValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._blog_comment_exchange("/blog/comment"), "xss")
        self.assertEqual(res.status, "confirmed",
                         f"stored-XSS leg missed a CSRF-token-bound form plant->render: {res.summary}")
        self.assertTrue(res.confirmed)

    def test_stored_xss_silent_on_escaped_csrf_bound_form_control(self):
        # NEGATIVE CONTROL: same CSRF-bound form flow, but the render escapes the
        # stored value -- the plant still succeeds (token refreshed, write stored),
        # so a non-confirm here proves the leg keys on the UNESCAPED render, not on
        # a successful write.
        self._blog_reset()
        v = StoredXssValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._blog_comment_exchange("/blog-safe/comment"), "xss")
        self.assertNotEqual(res.status, "confirmed")

    # --- JWT kid key-confusion (jwt_forge kid variant) ------------------------
    def _jwt_exchange(self, path):
        import base64 as _b, json as _j
        h = _b.urlsafe_b64encode(_j.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        p = _b.urlsafe_b64encode(_j.dumps({"role": "user", "sub": "alice"}).encode()).rstrip(b"=").decode()
        seed = f"{h}.{p}.Z2FyYmFnZQ"  # decodable header/payload, garbage signature
        return HttpExchange(url=f"{self._base}{path}", method="GET",
                            request_headers={"Authorization": f"Bearer {seed}"}, request_body="")

    def test_jwt_kid_confusion_confirms(self):
        v = JwtForgeValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._jwt_exchange("/jwt/kid"), "jwt")
        self.assertEqual(res.status, "confirmed",
                         f"jwt kid key-confusion not confirmed: {res.summary}")
        self.assertIn("kid", res.summary.lower())

    def test_jwt_kid_silent_on_fixed_secret_control(self):
        v = JwtForgeValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._jwt_exchange("/jwt/kid-safe"), "jwt")
        self.assertNotEqual(res.status, "confirmed")

    def test_jwt_unverified_signature_confirms(self):
        # An invalid-signature token accepted for authenticated access that a
        # tokenless request is denied -> the server does not verify the signature.
        v = JwtForgeValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._jwt_exchange("/jwt/unverified"), "jwt")
        self.assertEqual(res.status, "confirmed",
                         f"jwt leg missed an unverified-signature endpoint: {res.summary}")
        self.assertTrue(res.confirmed)
        self.assertIn("signature not verified", res.summary.lower())

    def test_jwt_unverified_silent_on_public_endpoint_control(self):
        # NEGATIVE CONTROL: a truly public endpoint accepts BOTH an invalid-signature
        # token and a tokenless request -> the token does not gate access, so the leg
        # must NOT claim a signature-verification bug (it skips / does not confirm).
        v = JwtForgeValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._jwt_exchange("/jwt/public"), "jwt")
        self.assertNotEqual(res.status, "confirmed")

    # --- File upload via a CSRF-bound multipart form (PortSwigger-shaped) ------
    def _upload_exchange(self, action, referer):
        # The captured upload request a real engagement supplies: a multipart POST
        # to the upload endpoint, with a Referer to the page that renders the form.
        return HttpExchange(
            url=f"{self._base}{action}", method="POST",
            request_headers={"Referer": f"{self._base}{referer}"},
            request_body="user=wiener")

    def test_file_upload_confirms_active_served_upload_via_form(self):
        v = FileUploadValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._upload_exchange("/upload/avatar", "/upload/account"),
                           "file_upload")
        self.assertEqual(res.status, "confirmed",
                         f"file-upload leg missed a CSRF-bound multipart upload served active: {res.summary}")
        self.assertTrue(res.confirmed)

    def test_file_upload_silent_on_attachment_served_control(self):
        # NEGATIVE CONTROL: identical upload flow, but the stored file is served as
        # an attachment (not an active execution context) -> must NOT confirm.
        v = FileUploadValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._upload_exchange("/upload/avatar-safe", "/upload/account-safe"),
                           "file_upload")
        self.assertNotEqual(res.status, "confirmed")

    # --- Excessive trust in client-side controls (client-supplied price) -------
    def _price_exchange(self, path):
        return HttpExchange(
            url=f"{self._base}{path}", method="POST",
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            request_body="productId=1&quantity=1&price=133700")

    def test_client_trust_confirms_reflected_price(self):
        v = ClientTrustValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._price_exchange("/shop/cart"), "business_logic")
        self.assertEqual(res.status, "confirmed",
                         f"client-trust leg missed a server-reflected client price: {res.summary}")
        self.assertTrue(res.confirmed)

    def test_client_trust_silent_on_server_priced_control(self):
        # NEGATIVE CONTROL: the server ignores the client price and uses its own, so
        # the tampered sentinel is never reflected -> must NOT confirm.
        v = ClientTrustValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._price_exchange("/shop/cart-safe"), "business_logic")
        self.assertNotEqual(res.status, "confirmed")

    def test_jwt_kid_confusion_through_run_context(self):
        from harness.run_context import RunContext
        ctx = RunContext.create(
            allowed_hosts=["127.0.0.1"], max_requests=8,
            gate_config={"active_enabled": True})
        validator = JwtForgeValidator(allowed_hosts=["127.0.0.1"], run_context=ctx)
        async def scenario():
            result = await validator.validate(
                _finding("jwt"), self._jwt_exchange("/jwt/kid"))
            await ctx.aclose()
            return result
        result = asyncio.run(scenario())
        self.assertEqual(result.status, "confirmed")
        self.assertGreaterEqual(ctx.budget.used, 2)

    # --- Driver-based request capture -> XXE confirm (LB-2) --------------------
    # /xxe/js-form has NO <form> and NO server-rendered link to /xxe/parse --
    # only a fetch() call inside its inline <script> POSTs the XML body. A
    # passive/HTML-only crawl has nothing to discover this shape from; only a
    # real browser executing the page's JS (driver_capture, reusing the same
    # Playwright engine/policy as browser_xss) observes the actual request.
    class _FakeRoleCrawlResult:
        """Minimal stand-in for RoleCrawlResult: driver_capture.discover()
        only needs a `.captured: list` attribute (see its docstring for why
        this module does not import harness.role_crawl)."""
        def __init__(self):
            self.captured: list = []

    @unittest.skipUnless(browser_driver.playwright_available(),
                         "playwright not installed")
    def test_driver_capture_feeds_js_built_xml_post_and_xxe_leg_confirms(self):
        rc = self._FakeRoleCrawlResult()
        obs = asyncio.run(driver_capture.discover(rc, f"{self._base}/xxe/js-form", wait_ms=1500))
        self.assertEqual(obs.load_error, "", f"driver capture failed to load the page: {obs.load_error}")
        matches = [e for e in rc.captured if e["url"].endswith("/xxe/parse")]
        self.assertEqual(len(matches), 1,
                         f"driver capture did not land the JS-issued POST /xxe/parse "
                         f"into RoleCrawlResult.captured: {rc.captured}")
        captured_exchange = matches[0]
        self.assertEqual(captured_exchange["method"], "POST")
        self.assertTrue((captured_exchange["request_body"] or "").lstrip().startswith("<?xml"),
                        "captured request body did not carry the real JS-built XML shape")

        ex = HttpExchange(**captured_exchange)
        v = XxeValidator(allowed_hosts=["127.0.0.1"])
        self.assertTrue(v.applies(_finding("xxe"), ex),
                        "xxe leg did not recognise the driver-captured exchange as XML-shaped")
        res = self._run_ex(v, ex, "xxe")
        self.assertEqual(res.status, "confirmed",
                         f"xxe leg did not confirm against the driver-captured JS-built XML POST: "
                         f"{res.summary}")
        self.assertTrue(res.confirmed)

    @unittest.skipUnless(browser_driver.playwright_available(),
                         "playwright not installed")
    def test_driver_capture_silent_on_js_built_xml_post_to_safe_control(self):
        rc = self._FakeRoleCrawlResult()
        asyncio.run(driver_capture.discover(rc, f"{self._base}/xxe/js-form-safe", wait_ms=1500))
        matches = [e for e in rc.captured if e["url"].endswith("/xxe/parse-safe")]
        self.assertEqual(len(matches), 1,
                         f"driver capture did not land the control POST: {rc.captured}")
        ex = HttpExchange(**matches[0])
        v = XxeValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, ex, "xxe")
        self.assertNotEqual(res.status, "confirmed",
                            "xxe leg FALSELY confirmed against the safe (non-resolving) control endpoint")

    def test_passive_only_synthesized_capture_misses_the_js_built_xxe_endpoint(self):
        """Negative control -- NO Playwright/browser involved, always runs (not
        skipped): builds the exchange the way role_crawl's PASSIVE discovery
        actually would for a POST endpoint it has no captured template for
        (_synthesize_body -- always a generic JSON guess, never XML), and with
        a finding class driver-capture's own content-shape discovery (not a
        pre-labelled "xxe" hypothesis) would produce. Proves the vulnerability
        confirmed above is one passive-only discovery misses: the xxe leg does
        not even recognise this shape as XML, let alone fire on it."""
        from harness.role_crawl import _synthesize_body
        body, ctype = _synthesize_body("POST", "/xxe/parse")
        self.assertEqual(ctype, "application/json")  # sanity: definitely not XML
        passive_exchange = HttpExchange(
            url=f"{self._base}/xxe/parse", method="POST",
            request_headers={"Content-Type": ctype}, request_body=body)
        v = XxeValidator(allowed_hosts=["127.0.0.1"])
        # A generic finding class (not "xxe") isolates applies() to the
        # content-shape check alone -- exactly what a shape-blind passive
        # discovery (no pre-labelled XXE hypothesis) would hand the leg.
        self.assertFalse(v.applies(_finding("business_logic"), passive_exchange),
                         "xxe leg incorrectly treated a passively-synthesized JSON body as XML-shaped")
        # The ONLY send-nothing leg: applies() is False, so validate() must skip
        # WITHOUT touching the fixture. Assert exactly zero requests (not merely
        # "not confirmed") -- this is the negative half of the Rule 4 guard.
        res = self._run_ex(v, passive_exchange, "xxe", expect_sent=False)
        self.assertNotEqual(res.status, "confirmed",
                            "a passive-only synthesized capture must NOT confirm the js-built XXE "
                            "endpoint -- that is exactly the gap driver-capture closes")

    # --- Browser XSS (Playwright, real Chromium) --------------------------------
    @unittest.skipUnless(browser_driver.playwright_available(),
                         "playwright not installed")
    def test_browser_xss_confirms_on_real_reflected_xss(self):
        v = BrowserXssValidator(allowed_hosts=["127.0.0.1"])
        res = self._run(v, "/xss/reflect?q=seed")
        self.assertEqual(res.status, "confirmed",
                         f"browser_xss leg did not confirm against a real reflected-XSS endpoint: {res.summary}")
        self.assertTrue(res.confirmed)

    @unittest.skipUnless(browser_driver.playwright_available(),
                         "playwright not installed")
    def test_browser_xss_silent_on_escaped_control(self):
        v = BrowserXssValidator(allowed_hosts=["127.0.0.1"])
        res = self._run(v, "/xss/safe?q=seed")
        self.assertNotEqual(res.status, "confirmed",
                            "browser_xss leg FALSELY confirmed on an escaped (safe) endpoint")

    # --- Cross-site browser PoC for CSRF (LB-5) --------------------------------
    # ONE no-defense positive + the FOUR controls (SameSite=Strict,
    # SameSite=Lax, Origin/Referer-enforced, bearer-only). The SameSite
    # controls are exercised directly against the PlaywrightDriver mechanism
    # (same victim endpoints as the positive -- SameSite enforcement is
    # entirely the browser's own job, nothing the fixture server varies on);
    # the positive, Origin-enforced, and bearer-only cases are exercised
    # through the full CsrfValidator.validate() leg.
    def _csrf_poc_reset(self):
        urllib.request.urlopen(urllib.request.Request(
            f"{self._base}/csrf-poc/reset", method="POST"), timeout=2).read()

    def _csrf_poc_exchange(self, path, cookie="csrf_sid=live-verify-session", headers=None):
        # Origin mirrors a real capture of a legitimate same-origin
        # submission -- the plain token-strip replay branch just forwards
        # it (2xx), so execution falls through to the NEW cross-site-PoC
        # branch, where the REAL browser's own unforgeable cross-origin
        # Origin header is what the fixture's Origin-enforced control
        # actually exercises.
        hdrs = {"Content-Type": "application/x-www-form-urlencoded", "Origin": self._base}
        if cookie:
            hdrs["Cookie"] = cookie
        if headers:
            hdrs.update(headers)
        return HttpExchange(url=f"{self._base}{path}", method="POST",
                            request_headers=hdrs, request_body="note=seed")

    @unittest.skipUnless(browser_driver.playwright_available(),
                         "playwright not installed")
    def test_csrf_cross_site_poc_confirms_no_defense_ambient_cookie(self):
        # THE POSITIVE: no SameSite/Origin/token defense -- the ambient
        # cookie rides along on a real cross-site auto-submit POST, and an
        # independent GET-only readback shows the state actually changed.
        self._csrf_poc_reset()
        v = CsrfValidator(allowed_hosts=["127.0.0.1"], cross_site_poc_enabled=True,
                          cross_site_readback_url=lambda u: u.replace("/transfer", "/state"))
        res = self._run_ex(v, self._csrf_poc_exchange("/csrf-poc/transfer"), "csrf")
        self.assertEqual(res.status, "confirmed",
                         f"csrf leg did not confirm the real cross-site browser PoC against a "
                         f"no-defense ambient-cookie victim: {res.summary}")
        self.assertTrue(res.confirmed)

    @unittest.skipUnless(browser_driver.playwright_available(),
                         "playwright not installed")
    def test_csrf_cross_site_poc_silent_on_origin_enforced_control(self):
        # CONTROL: the ambient cookie still rides along, but the fixture
        # rejects the browser's real, unforgeable cross-origin Origin header.
        self._csrf_poc_reset()
        v = CsrfValidator(allowed_hosts=["127.0.0.1"], cross_site_poc_enabled=True,
                          cross_site_readback_url=lambda u: u.replace("/transfer", "/state"))
        res = self._run_ex(v, self._csrf_poc_exchange("/csrf-poc/transfer-origin"), "csrf")
        self.assertNotEqual(res.status, "confirmed",
                            "csrf leg FALSELY confirmed against an Origin/Referer-enforced "
                            "victim despite the ambient cookie being present")

    @unittest.skipUnless(browser_driver.playwright_available(),
                         "playwright not installed")
    def test_csrf_cross_site_poc_silent_on_bearer_only_control(self):
        # CONTROL: non-ambient auth -- the browser's cookie jar can never
        # supply an Authorization header, so this must stay silent regardless
        # of cookie delivery.
        self._csrf_poc_reset()
        v = CsrfValidator(allowed_hosts=["127.0.0.1"], cross_site_poc_enabled=True,
                          cross_site_readback_url=lambda u: u.replace("/transfer", "/state"))
        ex = self._csrf_poc_exchange(
            "/csrf-poc/transfer-bearer", cookie=None,
            headers={"Authorization": "Bearer csrf-poc-fixture-bearer-token"})
        res = self._run_ex(v, ex, "csrf")
        self.assertNotEqual(res.status, "confirmed",
                            "csrf leg FALSELY confirmed a bearer-only (non-ambient) victim -- "
                            "the browser's cookie jar can never supply an Authorization header")

    @unittest.skipUnless(browser_driver.playwright_available(),
                         "playwright not installed")
    def test_cross_site_submit_silent_on_samesite_strict_control(self):
        # CONTROL, at the PlaywrightDriver mechanism level: an EXPLICIT
        # SameSite=Strict cookie must be blocked by the BROWSER'S OWN
        # enforcement on this cross-site top-level POST -- nothing in
        # cross_site_submit's own policy decides this.
        self._csrf_poc_reset()
        driver = browser_driver.default_driver()
        result = asyncio.run(driver.cross_site_submit(
            attacker_url="http://attacker.localhost/csrf-poc-attacker",
            victim_url=f"{self._base}/csrf-poc/transfer",
            readback_url=f"{self._base}/csrf-poc/state",
            form_fields={"note": "strict-control-probe-value"},
            cookie_name="csrf_sid", cookie_value="strict-session",
            cookie_domain=urlsplit(self._base).hostname,
            same_site="Strict"))
        self.assertEqual(result.load_error, "", f"PoC mechanism errored: {result.load_error}")
        self.assertNotIn("strict-control-probe-value", result.readback_body,
                         "SameSite=Strict should have blocked ambient-cookie delivery on the "
                         "cross-site POST, but the readback shows the state changed")

    @unittest.skipUnless(browser_driver.playwright_available(),
                         "playwright not installed")
    def test_cross_site_submit_silent_on_samesite_lax_control(self):
        # CONTROL, at the PlaywrightDriver mechanism level: an EXPLICIT
        # SameSite=Lax cookie blocks a cross-site top-level POST (Lax only
        # ever permits a cross-site top-level GET navigation).
        self._csrf_poc_reset()
        driver = browser_driver.default_driver()
        result = asyncio.run(driver.cross_site_submit(
            attacker_url="http://attacker.localhost/csrf-poc-attacker",
            victim_url=f"{self._base}/csrf-poc/transfer",
            readback_url=f"{self._base}/csrf-poc/state",
            form_fields={"note": "lax-control-probe-value"},
            cookie_name="csrf_sid", cookie_value="lax-session",
            cookie_domain=urlsplit(self._base).hostname,
            same_site="Lax"))
        self.assertEqual(result.load_error, "", f"PoC mechanism errored: {result.load_error}")
        self.assertNotIn("lax-control-probe-value", result.readback_body,
                         "SameSite=Lax should have blocked ambient-cookie delivery on the "
                         "cross-site POST, but the readback shows the state changed")


if __name__ == "__main__":
    unittest.main()
