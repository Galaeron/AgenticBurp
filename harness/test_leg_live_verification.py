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
from harness.validators.browser_xss_validator import BrowserXssValidator
from harness import browser_driver

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


class LiveLegVerificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import logging
        logging.getLogger("werkzeug").setLevel(logging.ERROR)  # quiet per-request logs
        global_throttle.configure(0)
        app = _load_make_app()()
        cls._server = make_server("127.0.0.1", 0, app, threaded=True)
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
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True})

    @classmethod
    def tearDownClass(cls):
        cls._server.shutdown()
        cls._thread.join(timeout=5.0)
        safety_gate.reset_default_gate()

    def _run(self, validator, path):
        ex = HttpExchange(url=f"{self._base}{path}", method="GET",
                          request_headers={}, request_body="")
        fc = next(iter(validator.finding_classes))
        return asyncio.run(validator.validate(_finding(fc), ex))

    def _run_ex(self, validator, exchange, fc):
        return asyncio.run(validator.validate(_finding(fc), exchange))

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


if __name__ == "__main__":
    unittest.main()
