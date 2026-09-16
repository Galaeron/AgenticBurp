"""Tests for the two new deferred legs: rate_limit (V4) and reset_token (V3).

The reset-token predictability oracle (analyze_tokens) is pure and gets the bulk
of the coverage; the validators get mocked-client behaviour + negative controls."""
import asyncio
import unittest
from unittest.mock import AsyncMock, patch, MagicMock

from harness.models import Finding, HttpExchange
from harness.safety_gate import SafetyGate, SafetyGateConfig, get_default_gate, reset_default_gate
from harness.validators.rate_limit_validator import RateLimitValidator
from harness.validators.reset_token_validator import ResetTokenValidator, analyze_tokens, _max_entropy_bits
from harness.run_context import RunContext, ScopePolicy
from harness.test_run_context import _Fixture


def _finding(vc):
    return Finding(vulnerability_class=vc, severity="medium", confidence=0.6,
                   summary="t", evidence="t", suggested_test="t", basis="derived")


def _ex(url="http://target.test/api/login", method="POST", body="user=alice&pass=x",
        headers=None, status=200):
    return HttpExchange(url=url, method=method, request_body=body,
                        request_headers=headers or {}, response_status=status, response_body="")


def _resp(status=200, text="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


# --- reset-token predictability oracle (pure) --------------------------------

class AnalyzeTokensTests(unittest.TestCase):
    def test_constant_token_is_predictable(self):
        ok, why = analyze_tokens(["abcd1234abcd1234abcd", "abcd1234abcd1234abcd"])
        self.assertTrue(ok)
        self.assertIn("CONSTANT", why)

    def test_sequential_integers_predictable(self):
        ok, why = analyze_tokens(["1001", "1002", "1003"])
        self.assertTrue(ok)

    def test_below_entropy_floor_predictable(self):
        # 6-digit numeric OTP: max ~20 bits, well below 64
        ok, why = analyze_tokens(["483920", "118273"])
        self.assertTrue(ok)
        self.assertIn("floor", why)

    def test_timestamp_shaped_predictable(self):
        ok, why = analyze_tokens(["1700000001", "1700000005"])
        self.assertTrue(ok)  # small-delta sequential OR timestamp

    def test_derived_from_email_predictable(self):
        import base64
        tok = base64.b64encode(b"alice@example.com").decode()
        ok, why = analyze_tokens([tok, tok + "x" * 40], known_values=["alice@example.com"])
        self.assertTrue(ok)
        self.assertIn("known value", why)

    def test_strong_random_tokens_not_confirmed(self):
        # two independent 43-char (256-bit) url-safe tokens: no deterministic weakness
        toks = ["Zx9Ke2Lm4Np7Qr1St3Uv5Wx8Yz0Ab2Cd4Ef6Gh8Ij0", "Kq2Lr4Mt6Nv8Pw0Qx2Ry4Sz6Ta8Ub0Vc2Wd4Xe6Yf8"]
        ok, why = analyze_tokens(toks)
        self.assertFalse(ok)

    def test_entropy_bits_helper(self):
        self.assertLess(_max_entropy_bits("123456"), 64)      # numeric OTP
        self.assertGreaterEqual(_max_entropy_bits("A" * 20), 0)
        self.assertGreater(_max_entropy_bits("Zx9Ke2Lm4Np7Qr1St3Uv5Wx8Yz0Ab2Cd4Ef6Gh8Ij0"), 64)

    def test_empty_is_not_confirmed(self):
        ok, _ = analyze_tokens([])
        self.assertFalse(ok)


# --- reset-token validator ----------------------------------------------------

class ResetTokenValidatorTests(unittest.TestCase):
    def setUp(self):
        reset_default_gate()
        get_default_gate({"active_enabled": True, "allow_mutating_replay": True})
        self.v = ResetTokenValidator(allowed_hosts=["target.test"], samples=3)

    def tearDown(self):
        reset_default_gate()

    def test_skip_out_of_scope(self):
        r = asyncio.run(self.v.validate(_finding("reset_token"),
                                        _ex(url="http://evil.test/reset")))
        self.assertEqual(r.status, "skipped")

    @patch("harness.validators.reset_token_validator.GatedAsyncClient")
    @patch("harness.global_throttle.acquire", new_callable=AsyncMock)
    def test_sequential_tokens_are_observation_not_confirmed(self, _t, mock_cls):
        # RETIRED (review 2026-09-09): a small-sample predictability PATTERN is an
        # observation; confirming needs a holdout prediction/acceptance test.
        seq = iter([_resp(200, '{"reset_token":"1001"}'),
                    _resp(200, '{"reset_token":"1002"}'),
                    _resp(200, '{"reset_token":"1003"}')])
        client = AsyncMock()
        client.request = AsyncMock(side_effect=lambda *a, **k: next(seq))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock()
        mock_cls.return_value = client
        r = asyncio.run(self.v.validate(_finding("reset_token"),
                                        _ex(url="http://target.test/api/reset", body="email=a@b.com")))
        self.assertEqual(r.status, "not_confirmed")
        self.assertFalse(r.confirmed)
        self.assertIn("holdout", r.summary.lower())

    @patch("harness.validators.reset_token_validator.GatedAsyncClient")
    @patch("harness.global_throttle.acquire", new_callable=AsyncMock)
    def test_not_confirmed_strong_tokens(self, _t, mock_cls):
        toks = ["Zx9Ke2Lm4Np7Qr1St3Uv5Wx8Yz0Ab2Cd4Ef6Gh8Ij0",
                "Kq2Lr4Mt6Nv8Pw0Qx2Ry4Sz6Ta8Ub0Vc2Wd4Xe6Yf8",
                "Mn3Op5Qr7St9Uv1Wx3Yz5Ab7Cd9Ef1Gh3Ij5Kl7Mn9"]
        it = iter([_resp(200, '{"token":"%s"}' % t) for t in toks])
        client = AsyncMock()
        client.request = AsyncMock(side_effect=lambda *a, **k: next(it))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock()
        mock_cls.return_value = client
        r = asyncio.run(self.v.validate(_finding("reset_token"),
                                        _ex(url="http://target.test/api/reset")))
        self.assertEqual(r.status, "not_confirmed")

    @patch("harness.validators.reset_token_validator.GatedAsyncClient")
    @patch("harness.global_throttle.acquire", new_callable=AsyncMock)
    def test_skip_when_no_token_observable(self, _t, mock_cls):
        it = iter([_resp(200, '{"status":"sent"}')] * 3)
        client = AsyncMock()
        client.request = AsyncMock(side_effect=lambda *a, **k: next(it))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock()
        mock_cls.return_value = client
        r = asyncio.run(self.v.validate(_finding("reset_token"),
                                        _ex(url="http://target.test/api/reset")))
        self.assertEqual(r.status, "skipped")
        self.assertIn("out-of-band", r.summary)


# --- rate-limit validator ------------------------------------------------------

class RateLimitValidatorTests(unittest.TestCase):
    def tearDown(self):
        reset_default_gate()

    def test_run_context_actual_burst_uses_session_and_budget(self):
        fixture = _Fixture()
        ctx = RunContext.create(
            allowed_hosts=["127.0.0.1"], max_requests=3,
            gate_config={"active_enabled": True, "allow_mutating_replay": True,
                         "max_burst_size": 3})
        ctx.sessions.register("user", "user", {"Authorization": "Bearer rate"},
                              allowed_origins=[ScopePolicy.origin_of(fixture.base)])
        validator = RateLimitValidator(
            allowed_hosts=["127.0.0.1"], min_attempts=3, run_context=ctx)
        exchange = _ex(url=fixture.base + "/login", headers={"Authorization": "Bearer rate"})
        async def scenario():
            result = await validator.validate(_finding("rate_limit"), exchange)
            await ctx.aclose()
            return result
        try:
            result = asyncio.run(scenario())
            self.assertEqual(result.status, "not_confirmed")
            self.assertEqual(ctx.budget.used, 3)
            self.assertEqual(len(fixture.httpd.received), 3)
            self.assertTrue(all(r["authorization"] == "Bearer rate"
                                for r in fixture.httpd.received))
        finally:
            fixture.close()

    def _gate(self, burst):
        reset_default_gate()
        get_default_gate({"active_enabled": True, "allow_mutating_replay": True,
                          "max_burst_size": burst})

    def test_skip_on_get(self):
        self._gate(20)
        v = RateLimitValidator(allowed_hosts=["target.test"], min_attempts=5)
        self.assertFalse(v.applies(_finding("rate_limit"), _ex(method="GET")))

    def test_skip_when_burst_ceiling_below_2(self):
        self._gate(1)  # ceiling 1 < minimum 2
        v = RateLimitValidator(allowed_hosts=["target.test"], min_attempts=5)
        r = asyncio.run(v.validate(_finding("rate_limit"), _ex()))
        self.assertEqual(r.status, "skipped")
        self.assertIn("below 2", r.summary)

    @patch("harness.validators.rate_limit_validator.httpx.AsyncClient")
    @patch("harness.global_throttle.acquire", new_callable=AsyncMock)
    def test_reduced_burst_is_observation_not_confirmed(self, _t, mock_cls):
        # RETIRED (review 2026-09-09): a small un-throttled burst is an observation,
        # never a confirmed rate-limit bypass.
        self._gate(3)  # ceiling 3 < min_attempts 5, but >= 2
        v = RateLimitValidator(allowed_hosts=["target.test"], min_attempts=5)
        client = AsyncMock()
        client.request = AsyncMock(return_value=_resp(200, "ok"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock()
        mock_cls.return_value = client
        r = asyncio.run(v.validate(_finding("rate_limit"), _ex()))
        self.assertEqual(r.status, "not_confirmed")
        self.assertFalse(r.confirmed)
        self.assertIn("observation", r.summary.lower())

    @patch("harness.validators.rate_limit_validator.httpx.AsyncClient")
    @patch("harness.global_throttle.acquire", new_callable=AsyncMock)
    def test_full_burst_no_throttle_is_observation_not_confirmed(self, _t, mock_cls):
        # RETIRED (review 2026-09-09): replaying a VALID request N times without a
        # 429 is an observation, not a confirmed lockout/rate-limit bypass.
        self._gate(20)
        v = RateLimitValidator(allowed_hosts=["target.test"], min_attempts=5)
        client = AsyncMock()
        client.request = AsyncMock(return_value=_resp(200, "ok"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock()
        mock_cls.return_value = client
        r = asyncio.run(v.validate(_finding("rate_limit"), _ex()))
        self.assertEqual(r.status, "not_confirmed")
        self.assertFalse(r.confirmed)
        self.assertIn("observation", r.summary.lower())

    @patch("harness.validators.rate_limit_validator.httpx.AsyncClient")
    @patch("harness.global_throttle.acquire", new_callable=AsyncMock)
    def test_not_confirmed_when_429(self, _t, mock_cls):
        self._gate(20)
        v = RateLimitValidator(allowed_hosts=["target.test"], min_attempts=5)
        calls = {"n": 0}

        async def _req(*a, **k):
            calls["n"] += 1
            return _resp(200, "ok") if calls["n"] < 3 else _resp(429, "Too Many Requests")
        client = AsyncMock()
        client.request = _req
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock()
        mock_cls.return_value = client
        r = asyncio.run(v.validate(_finding("rate_limit"), _ex()))
        self.assertEqual(r.status, "not_confirmed")
        self.assertFalse(r.confirmed)

    def test_blocked_when_mutating_replay_off(self):
        reset_default_gate()
        get_default_gate({"active_enabled": True, "allow_mutating_replay": False,
                          "max_burst_size": 20})
        v = RateLimitValidator(allowed_hosts=["target.test"], min_attempts=5)
        r = asyncio.run(v.validate(_finding("rate_limit"), _ex()))
        self.assertEqual(r.status, "skipped")


# --- registry integration ------------------------------------------------------

class RegistryTests(unittest.TestCase):
    def test_new_legs_registered_and_active(self):
        from harness.validators.registry import ValidatorRegistry
        reg = ValidatorRegistry({"validators": {"active_enabled": True}})
        self.assertIn("rate_limit", reg.validators)
        self.assertIn("reset_token", reg.validators)
        self.assertTrue(reg.validators["rate_limit"].active)
        self.assertTrue(reg.validators["reset_token"].active)


# --- auth_sequence multi-check routing ------------------------------------------

class AuthSequenceRoutingTests(unittest.TestCase):
    def test_generic_broken_auth_on_login_runs_enum(self):
        from harness.validators.auth_sequence_validator import AuthSequenceValidator
        v = AuthSequenceValidator(allowed_hosts=["target.test"])
        checks = v._which_checks("broken_authentication",
                                   _ex(url="http://target.test/api/login",
                                        body='{"username":"a","password":"b"}'))
        self.assertIn("enum", checks)
        self.assertIn("fixation", checks)

    def test_specific_enum_class_runs_only_enum(self):
        from harness.validators.auth_sequence_validator import AuthSequenceValidator
        v = AuthSequenceValidator(allowed_hosts=["target.test"])
        checks = v._which_checks("username_enumeration",
                                   _ex(url="http://target.test/api/login",
                                        body='{"username":"a","password":"b"}'))
        self.assertEqual(checks, ["enum"])

    def test_register_endpoint_runs_weak(self):
        from harness.validators.auth_sequence_validator import AuthSequenceValidator
        v = AuthSequenceValidator(allowed_hosts=["target.test"])
        checks = v._which_checks("broken_authentication",
                                   _ex(url="http://target.test/api/register",
                                        body='{"username":"a","password":"b"}'))
        self.assertEqual(checks, ["weak"])


if __name__ == "__main__":
    unittest.main()
