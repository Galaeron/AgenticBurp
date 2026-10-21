"""Code review 02, batch RV-M (I10/I11): a model label is not evidence, and coverage
records must say what was not tested.

M1  the engagement chain's missing-auth leg asserted `expected_protected=True` from a
    model label or a privileged-looking path, so a public-by-design route that answers
    anonymously was confirmed. Driven through ``Orchestrator.investigate_engagement``
    against an owned loopback server, with the real ``missing_auth_probe``.
M2  ``CoverageMatrix.not_tested()`` left BLOCKED, INCONCLUSIVE and ERROR cells off its
    list. Driven through ``build_coverage_driven`` (the production coverage driver).
M3  the ``fixation_confirm`` and ``stored_xss_confirm`` manifest rows described the
    retired oracles.
M4  leg_self_test's xss case ran (and silently failed) without Playwright instead of
    reporting that it needs Playwright. Driven through ``run_self_test`` and its owned
    fixture.
"""
from __future__ import annotations

import asyncio
import socketserver
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import yaml

from harness import (browser_driver, coverage_manifest as cm, engagement_builder, leg_self_test,
                     missing_auth_probe, role_crawl, worklist_investigator)
from harness.coverage_model import CellStatus, CoverageMatrix
from harness.engagement import EngagementState
from harness.orchestrator import Orchestrator
from harness.role_crawl import RoleSession
from harness.validators.base import ValidationResult

_HARNESS = Path(__file__).resolve().parent
_PUBLIC_DOCS = ("<h1>Administrator help</h1><p>Public documentation: how to request an "
                "administrator account and where to find the release notes.</p>")


class _Loopback:
    """Owned loopback server. `route(headers) -> (status, body)` answers every GET;
    each request is recorded as (path, lower-cased headers)."""

    def __init__(self, route):
        self.requests: list[tuple[str, dict]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                headers = {k.lower(): v for k, v in self.headers.items()}
                outer.requests.append((self.path, headers))
                status, body = route(headers)
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def server_bind(self):
                socketserver.TCPServer.server_bind(self)
                self.server_name, self.server_port = self.server_address[:2]

        self._server = Server(("127.0.0.1", 0), Handler)
        self.origin = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()


def _chain_config() -> dict:
    cfg = yaml.safe_load((_HARNESS / "config.yaml").read_text(encoding="utf-8")) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    cfg.setdefault("validators", {})["active_enabled"] = True
    cfg["validators"]["allow_mutating_replay"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = True
    eng = cfg.setdefault("engagement", {})
    eng["auto_escalate"] = False
    eng["feature_crawl"] = False
    eng["coverage_drive_legs"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["127.0.0.1"]
    return cfg


# ------------------------------------------------------------------ M1
class ChainMissingAuthDeclarationTests(unittest.TestCase):
    """M1 (R15 in the chain): only a protection declaration lets the missing-auth leg
    confirm; a model label or a privileged-looking path leaves a candidate."""

    _NODE = {"method": "GET", "path": "/admin/help", "reachable_roles": ["anonymous"],
             "template": {"method": "GET", "query": "", "body": "",
                          "content_type": "", "object_id": None}}

    def _run_chain(self, route, *, via: str):
        server = _Loopback(route)
        self.addCleanup(server.close)
        base = server.origin + "/"
        node = dict(self._NODE)
        label = {"vulnerability_class": "missing_authentication", "confidence": 0.6,
                 "severity": "high", "summary": "model: admin help is served without auth",
                 "evidence": "", "suggested_test": "", "basis": "agent"}

        async def build(base_url, roles, **kwargs):
            state = EngagementState(host="127.0.0.1")
            state.ingest_role_crawl({"endpoints": [{
                "method": "GET", "path": node["path"], "by_role": {"anonymous": 200},
                "reachable_roles": ["anonymous"], "object_scoped": False,
                "template": node["template"]}]})
            return state, role_crawl.RoleCrawlResult(base_url=base_url)

        async def investigate(*args, **kwargs):
            ex = worklist_investigator._seed_exchange(base, node, {}, "1")
            if via == "shape":
                findings = await kwargs["precondition_fn"](node, ex)
            else:
                await kwargs["confirm_fn"](label, ex)
                findings = [label]
            return [{"path": node["path"], "method": "GET", "findings_detail": findings,
                     "confirmed": any(f.get("confirmed") for f in findings)}]

        orch = Orchestrator(_chain_config())
        orch.allowed_hosts = ["127.0.0.1"]
        with patch.object(engagement_builder, "build_engagement", new=build), \
                patch.object(worklist_investigator, "investigate_worklist", new=investigate), \
                patch("harness.orchestrator_chain.review_captured_exchanges",
                      new=AsyncMock(return_value=0)), \
                patch("harness.orchestrator_chain.universal_header_audit",
                      new=AsyncMock(return_value=0)), \
                patch.object(orch, "_persist_confirmation_proof",
                             new=AsyncMock(return_value=(False, None, "test"))):
            result = asyncio.run(orch.investigate_engagement(
                base, [RoleSession("anonymous", {})], max_nodes=1, max_chain_rounds=0,
                discovery_max_probes=1))
        probes = [h for p, h in server.requests if p == "/admin/help"]
        return result["outcomes"][0]["findings_detail"], probes

    def _assert_anonymous_probe_ran(self, probes):
        self.assertEqual(len(probes), 1, "the missing-auth probe must have sent its request")
        self.assertFalse({"authorization", "cookie"} & set(probes[0]))

    def test_shape_labelled_public_route_stays_a_candidate(self):
        findings, probes = self._run_chain(lambda h: (200, _PUBLIC_DOCS), via="shape")
        self._assert_anonymous_probe_ran(probes)
        self.assertEqual(findings, [], "a privileged-looking path is not a protection "
                                       "declaration; the precondition leg must not confirm")

    def test_model_labelled_public_route_stays_unconfirmed(self):
        findings, probes = self._run_chain(lambda h: (200, _PUBLIC_DOCS), via="label")
        self._assert_anonymous_probe_ran(probes)
        self.assertFalse(findings[0].get("confirmed"), findings[0].get("evidence"))
        self.assertNotIn("confirmed_by_leg", findings[0])
        self.assertNotIn("missing-auth CONFIRMED", findings[0].get("evidence", ""))

    def test_denied_route_control_has_no_finding(self):
        findings, probes = self._run_chain(lambda h: (401, "login required"), via="shape")
        self._assert_anonymous_probe_ran(probes)
        self.assertEqual(findings, [])

    def test_declared_protected_route_with_baseline_still_confirms(self):
        """Positive control at the probe (the R15 rule the chain now defers to)."""
        # The leak: the declared-protected report is served whether or not the
        # caller's token is attached.
        server = _Loopback(lambda h: (200, '{"report": "q3 payroll", "rows": 41}'))
        self.addCleanup(server.close)
        outcome = asyncio.run(missing_auth_probe.probe(
            server.origin, ("GET", "/admin/report"), allowed_hosts=["127.0.0.1"],
            baseline_headers={"Authorization": "Bearer owner"}, send_garbage_token=False,
            expected_protected=True, protected_baseline=True))
        self.assertEqual(outcome.classification, "missing_auth")
        self.assertTrue(outcome.finding.confirmed)
        self.assertEqual([("authorization" in h) for _, h in server.requests], [False, True])


# ------------------------------------------------------------------ M2
class CoverageNotTestedListTests(unittest.TestCase):
    """M2: the coverage report's `not_tested` list names every cell that has no executed
    verdict -- blocked, inconclusive and errored legs included -- with a reason."""

    def _state(self):
        return SimpleNamespace(endpoints={"POST /search": SimpleNamespace(
            path="/search", method="POST", access={}, reachable_roles=[],
            object_scoped=False, findings=[], template=None)})

    def _drive(self, make_result):
        from harness.coverage_tracker import build_coverage_driven
        results = []

        async def run_leg(*args):
            result = await make_result()
            results.append(result)
            return result
        with patch.object(httpx.AsyncClient, "request",
                          AsyncMock(side_effect=AssertionError("unexpected network"))):
            report = asyncio.run(build_coverage_driven(
                self._state(), ["anonymous"], run_leg, driveable={"sqlmap"}, budget=1))
        return report, results

    @staticmethod
    def _driven(report):
        return [nt for nt in report["not_tested"]
                if nt["endpoint"] == "POST /search" and nt["status"] not in ("not_applicable",
                                                                             "skipped")]

    def _sqlmap_blocked(self):
        # RV-F's reviewer shape: the production validator refuses the POST and reports
        # "blocked" (the gate allows no mutating replay).
        from harness.models import Finding
        from harness.test_default_history_caller import _config, _exchange
        from harness.validators.sqlmap import SqlmapValidator
        cfg = _config()
        cfg["server"]["allowed_hosts"] = ["shop.invalid"]
        cfg["validators"].update(active_enabled=True, allow_mutating_replay=False)
        Orchestrator(cfg)
        ex = _exchange("http://shop.invalid/search",
                       {"Content-Type": "application/x-www-form-urlencoded"})
        ex.method, ex.request_body = "POST", "q=test"

        async def make():
            return await SqlmapValidator(allowed_hosts=["shop.invalid"]).validate(
                Finding(vulnerability_class="sqli", confidence=0.5, summary="candidate",
                        evidence="fixture", suggested_test="verify", basis="derived"), ex)
        return make

    def test_blocked_leg_is_listed_as_not_tested(self):
        report, results = self._drive(self._sqlmap_blocked())
        self.assertEqual([r.status for r in results], ["blocked"])
        listed = self._driven(report)
        self.assertEqual([nt["status"] for nt in listed], ["blocked"], report["not_tested"])
        self.assertTrue(listed[0]["reason"])
        # No double counting: the summary counts are unchanged by the list.
        self.assertEqual((report["blocked"], report["tested"]), (1, 0))

    def test_inconclusive_and_errored_legs_are_listed_with_reasons(self):
        for status in ("inconclusive", "error", "a-status-nobody-defined"):
            with self.subTest(status=status):
                async def make(status=status):
                    return ValidationResult("sqlmap", status, "sqli")
                report, _ = self._drive(make)
                listed = self._driven(report)
                expected = "error" if status == "error" else "inconclusive"
                self.assertEqual([nt["status"] for nt in listed], [expected],
                                 report["not_tested"])
                self.assertTrue(listed[0]["reason"])
                self.assertEqual(report[expected], 1)

    def test_executed_negative_and_confirmed_cells_stay_off_the_list(self):
        for status, confirmed in (("not_confirmed", False), ("confirmed", True)):
            with self.subTest(status=status):
                async def make(status=status, confirmed=confirmed):
                    return ValidationResult("sqlmap", status, "sqli", confirmed=confirmed)
                report, _ = self._drive(make)
                self.assertEqual(self._driven(report), [])
                self.assertEqual(report["tested"], 1)

    def test_matrix_lists_unexecuted_cells_without_a_recorded_reason(self):
        m = CoverageMatrix()
        for check_id, status in (("A", CellStatus.BLOCKED), ("B", CellStatus.INCONCLUSIVE),
                                 ("C", CellStatus.ERROR), ("D", CellStatus.NOT_DETECTED),
                                 ("E", CellStatus.CONTROLLED_NEGATIVE),
                                 ("F", CellStatus.CONFIRMED)):
            m.record("user", "GET /x", check_id, status=status, reason="")
        listed = {nt["check"]: nt for nt in m.not_tested()}
        self.assertEqual(sorted(listed), ["A", "B", "C"])
        self.assertTrue(all(nt["reason"] for nt in listed.values()))


# ------------------------------------------------------------------ M3
class ManifestCurrentRuleTests(unittest.TestCase):
    """M3: the two manifest rows describe the oracle RV-E/RV-E2 left, and name a test
    that exists and carries that row's caller evidence."""

    def _row(self, key):
        check_id, cls, method, label, desc = cm._CALLER_EVIDENCE[key]
        module, _, cls_name = cls.rpartition(".")
        test_cls = getattr(__import__(module, fromlist=[cls_name]), cls_name)
        fn = getattr(test_cls, method, None)
        self.assertIsNotNone(fn, f"{key} names a missing test {cls}.{method}")
        declared = cm.caller_evidence(key)
        self.assertEqual({k: fn.__coverage_evidence__[k] for k in declared}, declared)
        return desc.lower()

    def test_stored_xss_row_describes_browser_execution(self):
        desc = self._row("stored_xss_confirm")
        self.assertNotIn("raw render)", desc, "a raw render is a candidate since RV-E (R19)")
        for term in ("execut", "console", "computed", "candidate"):
            self.assertIn(term, desc)

    def test_fixation_row_describes_login_use_and_anonymous_denial(self):
        desc = self._row("fixation_confirm")
        for term in ("login succeeds", "authenticated", "anonymous", "denial"):
            self.assertIn(term, desc)


# ------------------------------------------------------------------ M4
class LegSelfTestXssPlaywrightTests(unittest.TestCase):
    """M4: without Playwright the stored-XSS self-test case says it needs Playwright and
    sends nothing; with a browser it still runs."""

    def _xss_case(self, calls):
        case = next(c for c in leg_self_test._default_cases() if c.marker == "xss")
        build_tp = case.build_tp

        def spy(base_url):
            calls.append(base_url)
            return build_tp(base_url)
        return case._replace(build_tp=spy)

    def test_without_playwright_the_case_reports_needs_playwright(self):
        calls, report = [], {}
        with patch.object(browser_driver, "playwright_available", return_value=False), \
                patch.object(browser_driver, "default_driver", return_value=None):
            case = self._xss_case(calls)
            self.assertFalse(case.available(), "the xss case must be gated on Playwright")
            live = leg_self_test.run_self_test(cases=[case], report_out=report)
        self.assertEqual(live, frozenset())
        self.assertEqual(calls, [], "an unavailable case must send nothing")
        self.assertEqual(report["xss"]["status"], "unavailable")
        self.assertIn("needs Playwright", report["xss"]["reason"])

    def test_with_a_browser_the_case_still_runs(self):
        from harness.test_leg_live_verification import _ParsedRenderExecutionDouble
        calls, report = [], {}
        with patch.object(browser_driver, "playwright_available", return_value=True), \
                patch.object(browser_driver, "default_driver",
                             return_value=_ParsedRenderExecutionDouble()):
            live = leg_self_test.run_self_test(cases=[self._xss_case(calls)],
                                               report_out=report)
        self.assertEqual(len(calls), 1)
        self.assertIn("xss", live, report)
        self.assertEqual(report["xss"]["status"], "live")

    @unittest.skipUnless(browser_driver.playwright_available(), "playwright not installed")
    def test_with_real_chromium_the_case_still_runs(self):
        report = {}
        live = leg_self_test.run_self_test(cases=[self._xss_case([])], report_out=report)
        self.assertIn("xss", live, report)

    def test_a_failed_pair_is_reported_with_its_reason(self):
        calls, report = [], {}
        with patch.object(browser_driver, "playwright_available", return_value=True), \
                patch.object(browser_driver, "default_driver", return_value=None):
            live = leg_self_test.run_self_test(cases=[self._xss_case(calls)],
                                               report_out=report)
        self.assertEqual(live, frozenset())
        self.assertEqual(report["xss"]["status"], "failed")
        self.assertIn("inconclusive", report["xss"]["reason"])


if __name__ == "__main__":
    unittest.main()
