"""WSTG-CONF-02 passive header adapter: the oracle, its cache key, and the
engagement coverage drive that calls it."""
import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

from harness import cache, store
from harness.coverage_model import CellStatus
from harness.models import Finding, HttpExchange
from harness.validators.security_headers_validator import (
    SecurityHeadersValidator, audit_security_headers)

_PATHS = {
    # Positive: a 2xx page without nosniff.
    "/api/plain": (200, {"Content-Type": "text/html"}),
    # Control: the owned headers hold.
    "/api/hardened": (200, {"Content-Type": "text/html", "X-Content-Type-Options": "nosniff",
                            "Referrer-Policy": "strict-origin"}),
    # A redirect the headers cannot speak for: skipped, never a negative.
    "/api/moved": (302, {"Location": "/login"}),
}


def _ex(status=200, headers=None, method="GET", url="http://t/a", body="<html></html>"):
    return HttpExchange(url=url, method=method, response_status=status,
                        response_headers=headers or {}, response_body=body)


def _finding():
    return Finding(vulnerability_class="misconfig", confidence=0.5, summary="", evidence="",
                   suggested_test="", basis="derived")


class AuditTests(unittest.TestCase):
    def verdict(self, *args, **kwargs):
        return audit_security_headers(_ex(*args, **kwargs))["verdict"]

    def test_missing_or_wrong_nosniff_fails(self):
        self.assertEqual(self.verdict(200, {}), "fail")
        self.assertEqual(self.verdict(200, {"X-Content-Type-Options": "sniff"}), "fail")
        # The first value is the one the Fetch standard reads.
        self.assertEqual(self.verdict(200, {"X-Content-Type-Options": "foo, nosniff"}), "fail")

    def test_nosniff_name_and_value_are_case_insensitive(self):
        self.assertEqual(self.verdict(200, {"x-content-type-options": "NoSniff"}), "pass")
        self.assertEqual(self.verdict(200, {"X-Content-Type-Options": "nosniff, foo"}), "pass")

    def test_referrer_policy_last_recognised_token_wins(self):
        ok = {"X-Content-Type-Options": "nosniff"}
        self.assertEqual(self.verdict(200, dict(ok, **{"Referrer-Policy": "no-referrer, unsafe-url"})), "fail")
        self.assertEqual(self.verdict(200, dict(ok, **{"Referrer-Policy": "unsafe-url, strict-origin"})), "pass")
        self.assertEqual(self.verdict(200, dict(ok, **{"Referrer-Policy": "unsafe-url, bogus"})), "fail")
        # Absent or unrecognised: the browser default, not a finding.
        self.assertEqual(self.verdict(200, ok), "pass")
        self.assertEqual(self.verdict(200, dict(ok, **{"Referrer-Policy": "bogus"})), "pass")

    def test_responses_the_headers_cannot_speak_for_are_skipped(self):
        for status in (None, 302, 404, 500, 204, 304):
            with self.subTest(status=status):
                self.assertEqual(self.verdict(status, {}), "skip")
        self.assertEqual(self.verdict(200, {}, method="HEAD"), "skip")

    def test_fingerprint_follows_the_policy_not_the_casing(self):
        one = audit_security_headers(_ex(200, {"X-Content-Type-Options": "NOSNIFF"}))
        two = audit_security_headers(_ex(200, {"x-content-type-options": "nosniff"}))
        self.assertEqual(one["fingerprint"], two["fingerprint"])
        self.assertNotEqual(one["fingerprint"], audit_security_headers(_ex(200, {}))["fingerprint"])


class ValidateTests(unittest.TestCase):
    def validate(self, exchange):
        return asyncio.run(SecurityHeadersValidator().validate(_finding(), exchange))

    def test_confirmed_is_a_low_severity_hardening_fact(self):
        res = self.validate(_ex(200, {}))
        self.assertEqual(res.status, "confirmed")
        self.assertTrue(res.confirmed)
        self.assertEqual(res.severity, "low")
        self.assertIn("X-Content-Type-Options is missing", res.summary)
        self.assertTrue(res.header_fingerprint)

    def test_control_and_skip(self):
        held = self.validate(_ex(200, {"X-Content-Type-Options": "nosniff"}))
        self.assertEqual(held.status, "not_confirmed")
        self.assertFalse(held.confirmed)
        skipped = self.validate(_ex(302, {}))
        self.assertEqual(skipped.status, "skipped")
        self.assertFalse(skipped.confirmed)

    def test_coverage_finding_takes_the_result_severity(self):
        from types import SimpleNamespace
        from harness.coverage_model import CHECKS_BY_ID
        from harness.orchestrator_helpers import coverage_confirmation_finding
        check = CHECKS_BY_ID["WSTG-CONF-02"]
        found = coverage_confirmation_finding(self.validate(_ex(200, {})), check, "http://t/a", "user")
        self.assertEqual(found["severity"], "low")
        legacy = SimpleNamespace(confirmed=True, finding_class="x", confidence=0.9, summary="s",
                                 evidence="", validator="v", header_fingerprint="")
        self.assertEqual(coverage_confirmation_finding(legacy, check, "http://t/a", "user")["severity"], "high")

    def test_cache_key_follows_the_captured_response(self):
        from harness.execution_registry import execution_key
        name = SecurityHeadersValidator.name
        plain, hardened = _ex(200, {}), _ex(200, {"X-Content-Type-Options": "nosniff"})
        # One request, two observed responses: two verdicts, never one shared.
        self.assertNotEqual(execution_key(name, plain, "misconfig"),
                            execution_key(name, hardened, "misconfig"))
        self.assertEqual(execution_key(name, plain, "misconfig"),
                         execution_key(name, _ex(200, {}), "misconfig"))


def _header_state(base, roles, **kwargs):
    from harness.engagement import EngagementState
    from harness.role_crawl import RoleCrawlResult
    state = EngagementState("localhost")
    for path, (status, headers) in _PATHS.items():
        for role in roles:
            state.record_template(base + path, "GET", HttpExchange(
                url=base + path, method="GET", request_headers=role.headers,
                response_status=status, response_headers=headers,
                response_body="" if status == 302 else "<html>fixture</html>"))
            if status == 200:
                # A second capture of the request that the oracle skips (a redirect)
                # must not hide the first capture's verdict.
                state.record_template(base + path, "GET", HttpExchange(
                    url=base + path, method="GET", request_headers=role.headers,
                    response_status=302, response_headers={"Location": "/login"}))
    for ep in state.endpoints.values():
        ep.reachable_roles = sorted({r.role for r in roles})
    return state, RoleCrawlResult(base_url=base)


class EngagementCallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        old = store._DB_PATH, cache._cache
        self.addCleanup(self.restore, old)
        store._DB_PATH = Path(self.temp.name) / "state.db"
        cache.init_cache(db_path=str(Path(self.temp.name) / "cache.db"))

    @staticmethod
    def restore(old):
        store._DB_PATH, cache._cache = old

    def run_caller(self, enabled, case_drive):
        from harness import test_smoke_investigate as smoke
        from harness.coverage_tracker import _LEG_CONFIRMATIONS
        from harness.orchestrator import Orchestrator
        from harness.test_coverage_capabilities import _controlled_model
        cfg = smoke._test_config()
        for name in _LEG_CONFIRMATIONS:
            cfg["validators"].setdefault(name, {})["enabled"] = False
        cfg["validators"]["security_headers"]["enabled"] = enabled
        orch = Orchestrator(cfg)
        _controlled_model(orch)
        orch.engagement_coverage_drive = True
        orch.engagement_coverage_case_drive = case_drive
        orch.run_active_probe = AsyncMock(return_value={
            "iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}})
        validator = orch.validator_registry.validators.get("security_headers")
        calls = AsyncMock(wraps=validator.validate) if validator else AsyncMock()
        if validator:
            validator.validate = calls
        sent = []

        async def _send(client, request, **kw):
            sent.append(str(request.url))
            raise httpx.ConnectError("offline fixture", request=request)

        with patch("harness.engagement_builder.build_engagement", side_effect=_header_state), \
                patch("httpx.AsyncClient.send", new=_send), \
                patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=smoke._responder(False)):
            result = asyncio.run(orch.investigate_engagement(
                smoke.BASE_URL, smoke.ROLES, max_nodes=0, step_budget=1, max_chain_rounds=0))
        rows = [r for r in result["coverage"]["phase_ledger"]["cells"] if r["check"] == "WSTG-CONF-02"]
        found = [f for f in result["findings"] if f.get("confirmed_by_leg") == SecurityHeadersValidator.name]
        return calls, rows, found, sent

    @staticmethod
    def by_path(rows):
        return {path: [r for r in rows if r["endpoint"].endswith(" " + path)] for path in _PATHS}

    def test_drive_confirms_controls_and_skips_without_sending(self):
        for case_drive in (False, True):
            with self.subTest(case_drive=case_drive):
                calls, rows, found, sent = self.run_caller(True, case_drive)
                self.assertGreater(calls.await_count, 0)
                rows = self.by_path(rows)
                for path in _PATHS:
                    self.assertTrue(rows[path], path)
                self.assertTrue(all(r["observation_status"] == CellStatus.CONFIRMED.value and r["conclusive"]
                                    for r in rows["/api/plain"]), rows["/api/plain"])
                self.assertTrue(all(r["observation_status"] == CellStatus.NOT_DETECTED.value
                                    for r in rows["/api/hardened"]), rows["/api/hardened"])
                # Skipped, never a negative (the case drive keeps the cell pending
                # over its skipped case).
                self.assertTrue(all(r["observation_status"] in (CellStatus.SKIPPED.value, CellStatus.PENDING.value)
                                    and not r["conclusive"] and r["terminal_reason"] == "leg_precondition_unmet"
                                    for r in rows["/api/moved"]), rows["/api/moved"])
                # Passive: the drive judged the captures and sent none of them.
                self.assertFalse([u for u in sent if any(p in u for p in _PATHS)], sent)
                self.assertTrue(found)
                self.assertTrue(all(f["url"].endswith("/api/plain") for f in found), found)
                self.assertTrue(all(f["severity"] == "low" for f in found), found)

    def test_disabled_adapter_is_unavailable_and_finds_nothing(self):
        calls, rows, found, _sent = self.run_caller(False, False)
        calls.assert_not_called()
        self.assertTrue(rows)
        self.assertTrue(all(r["terminal_reason"] == "validator_unavailable" for r in rows), rows)
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
