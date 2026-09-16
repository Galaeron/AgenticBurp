import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.models import Finding, HttpExchange, TestPlan
from harness.validators.sqlmap import SqlmapValidator
from harness.validators.registry import ValidatorRegistry


class FakeProc:
    returncode = 0
    stdout = "[INFO] parameter 'id' appears to be injectable\n[CRITICAL] GET parameter 'id' is vulnerable"
    stderr = ""


class ValidatorTests(unittest.TestCase):
    def setUp(self):
        self.exchange = HttpExchange(
            url="https://example.test/item?id=7",
            method="GET",
            request_headers={"User-Agent": "test"},
            response_status=200,
            response_body="item",
        )
        self.finding = Finding(
            vulnerability_class="sqli", confidence=0.8, severity="high",
            summary="possible SQL injection in id", evidence="id parameter",
            suggested_test="test id", basis="derived",
        )

    def test_raw_request_uses_captured_exchange_not_model_input(self):
        raw = SqlmapValidator._raw_request(self.exchange)
        self.assertIn("GET /item?id=7 HTTP/1.1", raw)
        self.assertIn("Host: example.test", raw)
        self.assertNotIn("sqlmap", raw)

    def test_registry_keeps_active_validators_off_by_default(self):
        reg = ValidatorRegistry({"validators": {"enabled": True, "active_enabled": False}})
        self.assertEqual(reg.for_finding(self.finding, self.exchange), [])

    def _idor_finding(self) -> Finding:
        return Finding(
            vulnerability_class="idor", confidence=0.8, severity="high",
            summary="possible IDOR on order id", evidence="id parameter",
            suggested_test="swap the id", basis="derived",
        )

    def test_runtime_toggle_arms_and_disarms_cross_identity(self):
        # Registered off (config default) -> the tester can arm it at run time
        # without a restart, and disarm it again. Nothing is persisted.
        reg = ValidatorRegistry({"validators": {"enabled": True, "active_enabled": True,
                                                 "cross_identity": {"enabled": False}}})
        self.assertFalse(reg.cross_identity_enabled())
        reg.set_cross_identity_enabled(True)
        self.assertTrue(reg.cross_identity_enabled())
        self.assertIn("cross_identity", reg.validators)
        # Idempotent: arming an already-armed validator does not double-register.
        before = reg.validators["cross_identity"]
        reg.set_cross_identity_enabled(True)
        self.assertIs(reg.validators["cross_identity"], before)
        reg.set_cross_identity_enabled(False)
        self.assertFalse(reg.cross_identity_enabled())
        self.assertNotIn("cross_identity", reg.validators)

    def test_runtime_active_toggle_gates_cross_identity_dispatch(self):
        # An armed cross-identity validator still only DISPATCHES when the active
        # gate is on -- flipping the gate at run time controls that.
        reg = ValidatorRegistry({"validators": {"enabled": True, "active_enabled": False,
                                                 "cross_identity": {"enabled": True}}})
        idor = self._idor_finding()
        self.assertEqual(reg.for_finding(idor, self.exchange), [])  # gate off
        reg.set_active_enabled(True)
        armed = [v.name for v in reg.for_finding(idor, self.exchange)]
        self.assertIn("cross_identity", armed)
        reg.set_active_enabled(False)
        self.assertEqual(reg.for_finding(idor, self.exchange), [])

    def test_state_reflects_live_gating(self):
        reg = ValidatorRegistry({"validators": {"enabled": True, "active_enabled": False,
                                                 "cross_identity": {"enabled": False}}})
        s = reg.state()
        self.assertEqual(s["enabled"], True)
        self.assertEqual(s["active_enabled"], False)
        self.assertEqual(s["cross_identity_enabled"], False)
        reg.set_active_enabled(True)
        reg.set_cross_identity_enabled(True)
        s = reg.state()
        self.assertTrue(s["active_enabled"])
        self.assertTrue(s["cross_identity_enabled"])
        self.assertIn("cross_identity", s["registered"])
        self.assertEqual(s["registered"], sorted(s["registered"]))

    def test_sqlmap_confirmation_promotes_only_on_explicit_tool_result(self):
        validator = SqlmapValidator()
        with patch("subprocess.run", return_value=FakeProc()):
            result = asyncio.run(validator.validate(self.finding, self.exchange))
        self.assertTrue(result.confirmed)
        self.assertEqual(result.status, "confirmed")

    def test_sqlmap_container_mode_wraps_in_docker_and_rewrites_localhost(self):
        from harness import tool_runner
        loopback_ex = HttpExchange(
            url="http://127.0.0.1:5002/api/item?id=7", method="GET",
            request_headers={"User-Agent": "t"}, response_status=200, response_body="x")
        validator = SqlmapValidator(container_image="harness/sqlmap:1.10.9")
        captured = {}
        def fake_run(cmd, *a, **k):
            captured["cmd"] = cmd
            return FakeProc()
        with patch("subprocess.run", fake_run), \
             patch("harness.tool_runner.available", return_value=(True, "ok")):
            asyncio.run(validator.validate(self.finding, loopback_ex))
        cmd = captured["cmd"]
        self.assertEqual(cmd[:3], [tool_runner.DOCKER, "run", "--rm"])   # ran in a container
        self.assertIn("harness/sqlmap:1.10.9", cmd)
        # the -u target was rewritten so the container reaches the host service
        u = cmd[cmd.index("-u") + 1]
        self.assertIn("host.docker.internal:5002", u)
        self.assertNotIn("127.0.0.1", u)

    def test_sqlmap_host_mode_unchanged_when_no_container_image(self):
        validator = SqlmapValidator()  # no container_image
        captured = {}
        def fake_run(cmd, *a, **k):
            captured["cmd"] = cmd
            return FakeProc()
        with patch("subprocess.run", fake_run):
            asyncio.run(validator.validate(self.finding, self.exchange))
        self.assertEqual(captured["cmd"][0], "sqlmap")  # host binary, no docker wrapping

    def test_sqlmap_failure_is_not_confirmation(self):
        class NoHit:
            returncode = 0
            stdout = "[INFO] testing parameter id"
            stderr = ""
        validator = SqlmapValidator()
        with patch("subprocess.run", return_value=NoHit()):
            result = asyncio.run(validator.validate(self.finding, self.exchange))
        self.assertFalse(result.confirmed)
        self.assertEqual(result.status, "not_confirmed")

    def test_timeout_with_bytes_partial_output_does_not_crash(self):
        """
        Regression test for a real bug found live: subprocess.run's
        TimeoutExpired can carry .stdout/.stderr as bytes even when the
        call passed text=True -- confirmed by triggering a genuine
        sqlmap timeout against a real target (a slower, more thorough
        scan legitimately exceeded the configured timeout). The old
        code did `(exc.stdout or "") + "\\n" + (exc.stderr or "")`,
        which crashes with TypeError the moment either side is bytes --
        turning a normal "sqlmap took too long" outcome into an
        unhandled crash instead of the intended graceful error result.
        No prior test exercised this path at all.
        """
        import subprocess
        validator = SqlmapValidator()
        timeout_exc = subprocess.TimeoutExpired(
            cmd=["sqlmap"], timeout=90,
            output=b"[INFO] testing parameter id\npartial output",
            stderr=b"some stderr bytes",
        )
        with patch("subprocess.run", side_effect=timeout_exc):
            result = asyncio.run(validator.validate(self.finding, self.exchange))
        self.assertEqual(result.status, "error")
        self.assertIn("timed out", result.summary)
        self.assertIn("partial output", result.evidence)
        self.assertIn("some stderr bytes", result.evidence)

    def test_timeout_with_str_partial_output_still_works(self):
        """Companion to the bytes case above -- confirms the fix handles
        the str form too (e.g. a different Python/OS combination that
        does decode consistently), not just bytes."""
        import subprocess
        validator = SqlmapValidator()
        timeout_exc = subprocess.TimeoutExpired(
            cmd=["sqlmap"], timeout=90,
            output="already a str", stderr="also already a str",
        )
        with patch("subprocess.run", side_effect=timeout_exc):
            result = asyncio.run(validator.validate(self.finding, self.exchange))
        self.assertEqual(result.status, "error")
        self.assertIn("already a str", result.evidence)

    def test_timeout_with_no_partial_output_does_not_crash(self):
        """Edge case: a timeout with no captured output at all (both
        None) must still produce a clean error result, not crash on the
        concatenation."""
        import subprocess
        validator = SqlmapValidator()
        timeout_exc = subprocess.TimeoutExpired(cmd=["sqlmap"], timeout=90)
        with patch("subprocess.run", side_effect=timeout_exc):
            result = asyncio.run(validator.validate(self.finding, self.exchange))
        self.assertEqual(result.status, "error")
        self.assertEqual(result.evidence, "\n")


class EveryActiveValidatorPlanMethodWorksTests(unittest.TestCase):
    """
    Regression test for a severe, previously-undiscovered bug found the
    first time this project ever actually flipped
    validators.active_enabled=True in a real run (against a live Juice
    Shop instance): 12 of the 13 active validators' plan() methods
    constructed a TestPlan using fields that don't exist on that model
    at all (target_url, target_method, description, parameters,
    expected_outcome -- all silently ignored by pydantic's default
    extra="ignore") while never setting the two REQUIRED fields
    (finding_class, source_exchange_url) -- crashing with a
    ValidationError the instant orchestrator._validate_findings() tried
    to build a plan for any finding any of them applied to. Only
    sqlmap.py's plan() was ever written against the real schema. No
    existing test constructed a real ValidatorRegistry with
    active_enabled=True and called plan() on every validator it
    produces -- which is exactly why this went unnoticed. This test
    exists to close that blind spot for good.
    """

    def setUp(self):
        self.exchange = HttpExchange(
            url="https://example.test/item?id=7", method="GET",
            request_headers={"User-Agent": "test"}, response_status=200, response_body="item",
        )
        self.finding = Finding(
            vulnerability_class="sqli", confidence=0.8, severity="high",
            summary="possible SQL injection in id", evidence="id parameter",
            suggested_test="test id", basis="derived",
        )

    def test_every_active_validators_plan_method_builds_a_valid_test_plan(self):
        registry = ValidatorRegistry({"validators": {"active_enabled": True}})
        active_validators = [v for v in registry.validators.values() if v.active]
        # 13 as of this writing (see registry.py) -- sqlmap, cors, recon,
        # http_request_smuggling, web_cache_poisoning, oauth,
        # subdomain_takeover, crypto, csp, header_injection,
        # api_security, websocket, race_condition.
        self.assertGreaterEqual(len(active_validators), 13)

        failures = []
        for validator in active_validators:
            try:
                plan = validator.plan(self.finding, self.exchange)
            except Exception as e:
                failures.append(f"{validator.name}: raised {type(e).__name__}: {e}")
                continue
            if plan is None:
                continue  # a validator may legitimately decline to plan for this finding
            if not isinstance(plan, TestPlan):
                failures.append(f"{validator.name}: plan() returned {type(plan).__name__}, not a TestPlan")
                continue
            if not plan.finding_class:
                failures.append(f"{validator.name}: TestPlan.finding_class is empty")
            if not plan.source_exchange_url:
                failures.append(f"{validator.name}: TestPlan.source_exchange_url is empty")

        self.assertEqual(
            failures, [],
            "One or more active validators' plan() method is broken "
            "(this is exactly the bug class this test exists to catch):\n" + "\n".join(failures),
        )

    def test_different_exchanges_to_the_same_url_get_different_plan_ids(self):
        """
        Regression test for a second real bug found in the same live
        Juice Shop run that motivated the test above: all 12 validators'
        plan_id generation used only (vulnerability_class, exchange.url),
        ignoring the rest of the exchange. Two real, different login
        attempts to the same /rest/user/login URL produced the EXACT
        SAME plan_id, so the second one's persist_test_plans() call
        silently clobbered (or was ignored against) the first's stored
        source_exchange_hash -- and the first request's later validation
        submission was then rejected with "binding_mismatch". Confirmed
        live, not hypothetical. The fix reuses the already-computed
        full-exchange hash for the plan_id too, not just
        source_exchange_hash.
        """
        registry = ValidatorRegistry({"validators": {"active_enabled": True}})
        active_validators = [v for v in registry.validators.values() if v.active]

        exchange_a = HttpExchange(
            url="https://example.test/rest/user/login", method="POST",
            request_headers={"Content-Type": "application/json"},
            request_body='{"email": "admin@example.test", "password": "a"}',
            response_status=200, response_body='{"ok": true}',
        )
        exchange_b = HttpExchange(
            url="https://example.test/rest/user/login", method="POST",
            request_headers={"Content-Type": "application/json"},
            request_body='{"email": "admin@example.test\' -- ", "password": "anything"}',
            response_status=200, response_body='{"ok": true, "admin": true}',
        )

        failures = []
        for validator in active_validators:
            plan_a = validator.plan(self.finding, exchange_a)
            plan_b = validator.plan(self.finding, exchange_b)
            if plan_a is None or plan_b is None:
                continue
            if plan_a.id == plan_b.id:
                failures.append(f"{validator.name}: same plan_id for two different exchanges to the same URL")
            if plan_a.source_exchange_hash == plan_b.source_exchange_hash:
                failures.append(f"{validator.name}: same source_exchange_hash for two different exchanges")

        self.assertEqual(
            failures, [],
            "One or more active validators still collide plan_ids across different exchanges "
            "to the same URL:\n" + "\n".join(failures),
        )


class _FakeResponse:
    """Minimal httpx.Response stand-in for CORS validator unit tests."""
    def __init__(self, headers):
        self.headers = headers


class CorsWildcardGateTests(unittest.TestCase):
    """A bare `Access-Control-Allow-Origin: *` without credentials must NOT
    be reported as a vulnerability (Juice Shop full-run: this was 58 of 60
    false 'confirmed' findings). The dangerous wildcard+credentials
    combination MUST still confirm."""

    def setUp(self):
        from harness.validators.cors_validator import CorsValidator
        self.validator = CorsValidator()
        self.exchange = HttpExchange(
            url="https://example.test/api/products",
            method="GET",
            request_headers={"User-Agent": "test"},
            response_status=200,
            response_body="{}",
        )

    def _run_wildcard(self, headers):
        async def fake_send(*args, **kwargs):
            return _FakeResponse(headers)
        with patch.object(self.validator, "_send_request", side_effect=fake_send):
            return asyncio.run(
                self.validator._test_wildcard_origin("https://example.test", self.exchange)
            )

    def test_bare_wildcard_is_informational_not_vulnerable(self):
        result = self._run_wildcard({"Access-Control-Allow-Origin": "*"})
        self.assertFalse(result.vulnerable)
        self.assertEqual(result.severity, "info")

    def test_wildcard_with_credentials_is_vulnerable(self):
        result = self._run_wildcard({
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        })
        self.assertTrue(result.vulnerable)
        self.assertEqual(result.severity, "critical")

    def test_arbitrary_origin_reflection_still_vulnerable(self):
        result = self._run_wildcard(
            {"Access-Control-Allow-Origin": "https://evil-attacker.com"}
        )
        self.assertTrue(result.vulnerable)

    def _run_vary(self, headers):
        async def fake_send(*args, **kwargs):
            return _FakeResponse(headers)
        with patch.object(self.validator, "_send_request", side_effect=fake_send):
            return asyncio.run(
                self.validator._test_vary_origin("https://example.test", self.exchange)
            )

    def test_missing_vary_with_static_wildcard_is_informational(self):
        # Missing Vary: Origin but ACAO is a static wildcard -> nothing
        # origin-specific to cache-poison -> not a vulnerability.
        result = self._run_vary({"Access-Control-Allow-Origin": "*"})
        self.assertFalse(result.vulnerable)
        self.assertEqual(result.severity, "info")

    def test_missing_vary_with_reflected_origin_is_vulnerable(self):
        result = self._run_vary({"Access-Control-Allow-Origin": "https://evil-attacker.com"})
        self.assertTrue(result.vulnerable)

    def test_vary_origin_present_is_not_vulnerable(self):
        result = self._run_vary({"Access-Control-Allow-Origin": "*", "Vary": "Origin"})
        self.assertFalse(result.vulnerable)


if __name__ == "__main__":
    unittest.main()
