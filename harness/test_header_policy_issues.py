"""Response-header policy findings are one issue per site (2026-11-13).

r10 (job 9eb242afd5a0) stored 101 csp_validator rows on 45 routes of one origin.
Every row recorded the same observed policy: no CSP, no CSP-Report-Only,
X-Frame-Options SAMEORIGIN. The findings API, issues export and report still
showed 49 confirmed csp issues, one per route, because the stored rows carry no
policy fingerprint. issues.header_policy now keys a header-policy row on origin +
canonical class + header names + the observed value its record holds. When no
value is recorded it keys on the header names only, and the issue says the routes
may differ. Rows stay per route; only the grouping changes.

Production callers: rows come from Orchestrator.investigate_engagement's coverage
drive (the real CspValidator and SecurityHeadersValidator against loopback pages,
bound by store.bind_confirmation_proof) and from store.persist_findings, as
analyze stores a model's claims. Issues come from
report_generator.export_issues_for_host (findings API, /issues, SARIF) and
generate_report_for_host (the Markdown report). Every send stays on 127.0.0.1.
"""
import asyncio
import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import AsyncMock, patch

from harness import cache, global_throttle, issues, report_generator, safety_gate, store
from harness.evidence import ProofRecord, TestCaseRef
from harness.models import Finding, HttpExchange

_CSP_HEADERS = ["content-security-policy", "content-security-policy-report-only", "x-frame-options"]
_HTML = b"<html><head><title>page</title></head><body>page</body></html>"


class _Pages(BaseHTTPRequestHandler):
    """Every path is an HTML page; `server.headers_for(path)` adds its headers."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        self.server.received.append(path)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for name, value in self.server.headers_for(path).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(_HTML)))
        self.end_headers()
        self.wfile.write(_HTML)


def _dump(value):
    if isinstance(value, dict):
        value = {str(k): v for k, v in value.items()}
    return json.dumps(value, indent=1, default=str)[:4000]


class _HeaderCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="header_issues_")
        self._saved = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()
        st = global_throttle.throttle.stats()
        prev = (st["rate_per_second"] if st["enabled"] else 0.0, st["burst"] if st["enabled"] else None)
        self.addCleanup(lambda: global_throttle.configure(*prev))
        global_throttle.configure(0)

    def tearDown(self):
        store._DB_PATH, cache._cache = self._saved
        safety_gate.reset_default_gate()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def site(self, headers_for=None) -> str:
        """A loopback site of HTML pages; returns its origin."""
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Pages)
        server.received = []
        server.headers_for = headers_for or (lambda path: {})
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}"

    @staticmethod
    def capture(url) -> HttpExchange:
        try:
            with urllib.request.urlopen(url) as resp:
                status, headers, body = resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as err:
            status, headers, body = err.code, dict(err.headers), err.read()
        return HttpExchange(url=url, method="GET", response_status=status, response_headers=headers,
                            response_body=body.decode("utf-8", errors="replace"))

    def drive(self, origin, paths, families=("csp",)):
        """The engagement coverage drive over captures of `paths`, with only
        `families`' legs enabled (as harness.test_coverage_proof_binding drives it)."""
        from harness import test_smoke_investigate as smoke
        from harness.coverage_tracker import _LEG_CONFIRMATIONS
        from harness.engagement import EngagementState
        from harness.orchestrator import Orchestrator
        from harness.role_crawl import RoleCrawlResult, RoleSession
        from harness.run_context import RunContext
        from harness.test_coverage_capabilities import _controlled_model
        captures = {path: self.capture(origin + path) for path in paths}
        cfg = smoke._test_config()
        for name in _LEG_CONFIRMATIONS:
            cfg["validators"].setdefault(name, {})["enabled"] = False
        for name in families:
            cfg["validators"][name]["enabled"] = True
        orch = Orchestrator(cfg)
        _controlled_model(orch)
        orch.business_context_enabled = False
        orch.engagement_coverage_drive = True
        orch.engagement_coverage_case_drive = True
        orch.run_active_probe = AsyncMock(return_value={"iterative_result": {"findings": []}, "integration": {}})

        def build(*args, **kwargs):
            state = EngagementState("127.0.0.1")
            for path, ex in captures.items():
                state.record_template(origin + path, "GET", ex)
            for ep in state.endpoints.values():
                ep.reachable_roles = ["anonymous"]
            return state, RoleCrawlResult(base_url=origin)

        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=400, config=cfg,
                                gate_config={"active_enabled": True})

        async def run():
            async with ctx:
                return await orch.investigate_engagement(
                    origin, [RoleSession("anonymous", {})], max_nodes=0, step_budget=1,
                    max_chain_rounds=0, active_discovery=False, run_context=ctx)

        with patch("harness.engagement_builder.build_engagement", side_effect=build):
            return asyncio.run(run())

    @staticmethod
    def claim(url, cls, *, agent="headers_agent", severity="medium", confidence=0.4,
              evidence="the model's own reading of the response"):
        """A model's unconfirmed claim, stored as analyze stores it."""
        store.persist_findings(HttpExchange(url=url, method="GET", response_status=200), agent, [Finding(
            vulnerability_class=cls, severity=severity, confidence=confidence, summary=f"{cls} claim",
            evidence=evidence, suggested_test="verify", basis="derived")])

    def legacy_confirmed(self, url, cls, *, severity="medium", confidence=0.9):
        """A confirmed row whose stored proof records no header value: what a run
        from before csp evidence named its values left in the store."""
        case = TestCaseRef.make(run_id="run-legacy", request_template_id=f"GET {url}", check_id="csp",
                                principal_id="captured")
        proof = ProofRecord.from_validation_result(
            case=case, validator="csp_validator", status="confirmed", confirmed=True,
            validator_version="1", executed=True, baseline_artifact_id=f"{url}-b",
            attack_artifact_id=f"{url}-a", control_artifact_ids=(f"{url}-c",))
        ok, why = store.persist_proof_record(proof)
        self.assertTrue(ok, why)
        store.persist_findings(HttpExchange(url=url, method="GET", response_status=200), "csp", [Finding(
            vulnerability_class=cls, severity=severity, confidence=confidence, summary=f"{cls} on {url}",
            evidence="stored before header values were recorded", suggested_test="verify",
            basis="derived", confirmed=True, proof_id=proof.proof_id, case_id=case.case_id)])

    @staticmethod
    def rows(origin, agent=None):
        return [r for r in store.all_host_findings(origin + "/") if agent is None or r["agent"] == agent]

    @staticmethod
    def issues(origin, cls=None):
        return [i for i in report_generator.export_issues_for_host(origin + "/")
                if cls is None or i["vulnerability_class"] == cls]

    @staticmethod
    def report(origin):
        return report_generator.generate_report_for_host(origin + "/")


class RecordedPolicyIssueTests(_HeaderCase):
    def test_one_absent_policy_on_many_routes_is_one_issue_listing_every_route(self):
        origin = self.site()
        paths = ("/about", "/contact", "/help", "/home")
        self.drive(origin, paths)
        rows = self.rows(origin, "csp_validator")
        # The findings table keeps its per-route rows, every one confirmed.
        self.assertEqual({r["url"] for r in rows}, {origin + p for p in paths}, _dump(rows))
        self.assertTrue(all(r["confirmed"] for r in rows))

        csp = self.issues(origin, "csp")
        self.assertEqual(len(csp), 1, _dump(csp))
        issue = csp[0]
        self.assertEqual(issue["affected_routes"], list(paths))
        self.assertEqual(issue["instances_count"], len(rows))
        self.assertEqual(sorted(issue["member_ids"]), sorted(r["fingerprint"] for r in rows))
        self.assertEqual(issue["evidence_state"], "confirmed")
        self.assertEqual(issue["header_policy"], {
            "headers": _CSP_HEADERS, "recorded": True,
            "observed": dict.fromkeys(_CSP_HEADERS, "absent")})
        self.assertEqual(issue["route_status"], dict.fromkeys(paths, "confirmed"))
        self.assertFalse([line for line in issue["limitations"] if "may differ" in line])

        report = self.report(origin)
        self.assertEqual(report.count("_Issue: `" + issue["issue_id"] + "`"), 1, report)
        self.assertIn("one recorded header policy", report)
        for path in paths:
            self.assertIn(origin + path, report)
        self.assertNotIn("may differ", report)

        # Control: without the recorded-policy key the same rows are one issue per route.
        with patch.object(issues, "header_policy", return_value=None):
            self.assertEqual(sorted(len(i["affected_instances"]) for i in self.issues(origin, "csp")),
                             [1] * len(paths))

    def test_two_recorded_csp_values_are_two_issues(self):
        weak = "script-src 'self' 'unsafe-inline'; object-src 'none'"
        broad = "script-src *; object-src 'none'"
        values = {"/a": weak, "/b": broad, "/c": weak,
                  "/d": "Script-Src  'self'   'unsafe-inline'; object-src 'none'"}   # the same policy
        origin = self.site(lambda path: {"Content-Security-Policy": values[path], "X-Frame-Options": "DENY"}
                           if path in values else {})
        self.drive(origin, tuple(values))
        self.assertEqual({r["url"] for r in self.rows(origin, "csp_validator")},
                         {origin + p for p in values})
        csp = self.issues(origin, "csp")
        self.assertEqual(sorted(i["affected_routes"] for i in csp), [["/a", "/c", "/d"], ["/b"]], _dump(csp))
        observed = {tuple(i["affected_routes"]): i["header_policy"]["observed"] for i in csp}
        self.assertEqual(observed[("/b",)]["content-security-policy"], broad)
        self.assertEqual(" ".join(observed[("/a", "/c", "/d")]["content-security-policy"].lower().split()),
                         weak.lower())
        self.assertTrue(all(i["header_policy"]["recorded"] and i["evidence_state"] == "confirmed"
                            for i in csp))

    def test_two_origins_are_two_issues(self):
        first, second = self.site(), self.site()
        self.drive(first, ("/about", "/home"))
        self.drive(second, ("/about", "/home"))
        for origin in (first, second):
            csp = self.issues(origin, "csp")
            self.assertEqual([sorted(i["affected_instances"]) for i in csp],
                             [[origin + "/about", origin + "/home"]], _dump(csp))
        self.assertNotEqual(self.issues(first, "csp")[0]["issue_id"], self.issues(second, "csp")[0]["issue_id"])

    def test_security_header_audit_failures_are_one_issue_per_recorded_failure(self):
        def headers(path):
            return {"/c": {"X-Content-Type-Options": "nosniff", "Referrer-Policy": "unsafe-url"},
                    "/d": {"X-Content-Type-Options": "nosniff"}}.get(path, {})
        origin = self.site(headers)
        self.drive(origin, ("/a", "/b", "/c", "/d"), families=("security_headers",))
        audit = self.rows(origin, "security_headers_validator")
        self.assertEqual({r["url"] for r in audit}, {origin + p for p in ("/a", "/b", "/c")}, _dump(audit))
        # A model's own misconfiguration claim on an audited route is not the audit's.
        self.claim(origin + "/a", "misconfig", evidence="X-Content-Type-Options is missing")
        grouped = {tuple(i["affected_routes"]) if "header_policy" in i else ("claim", i["endpoint_family"]): i
                   for i in self.issues(origin, "misconfig")}
        self.assertEqual(set(grouped), {("/a", "/b"), ("/c",), ("claim", "/a")}, _dump(grouped))
        self.assertEqual(grouped[("/a", "/b")]["header_policy"]["observed"], {"x-content-type-options": "absent"})
        self.assertEqual(grouped[("/c",)]["header_policy"]["observed"], {"referrer-policy": "unsafe-url"})
        self.assertEqual(grouped[("claim", "/a")]["evidence_state"], "candidate")


class MixedAndUnrecordedTests(_HeaderCase):
    ORIGIN = "http://shop.test"

    def test_mixed_confirmed_and_candidate_group_is_confirmed_with_per_route_status(self):
        o = self.ORIGIN
        self.legacy_confirmed(o + "/legacy", "Missing Content-Security-Policy", severity="medium",
                              confidence=0.9)
        self.claim(o + "/x", "Missing Content-Security-Policy header", severity="low", confidence=0.4)
        self.claim(o + "/y", "missing content security policy", severity="high", confidence=0.3)
        self.claim(o + "/z", "Missing X-Frame-Options")              # another header: its own issue
        self.assertEqual(len(self.rows(o)), 4)
        csp = self.issues(o, "csp")
        self.assertEqual(sorted(i["affected_routes"] for i in csp), [["/legacy", "/x", "/y"], ["/z"]],
                         _dump(csp))
        issue = next(i for i in csp if len(i["affected_routes"]) == 3)
        self.assertEqual(issue["evidence_state"], "confirmed")
        self.assertEqual(issue["route_status"], {"/legacy": "confirmed", "/x": "candidate", "/y": "candidate"})
        self.assertEqual((issue["severity"], issue["confidence"]), ("high", 0.9))
        self.assertEqual(issue["header_policy"], {"headers": ["content-security-policy"], "recorded": False,
                                                  "observed": {}})
        self.assertTrue(any("may differ" in line for line in issue["limitations"]), issue["limitations"])
        other = next(i for i in csp if i["affected_routes"] == ["/z"])
        self.assertEqual((other["evidence_state"], other["header_policy"]["headers"]),
                         ("candidate", ["x-frame-options"]))

        report = self.report(o)
        self.assertEqual(report.count("_Issue: `" + issue["issue_id"] + "`"), 1, report)
        self.assertIn(f"`{o}/legacy` (confirmed)", report)
        self.assertIn(f"`{o}/x` (candidate)", report)
        self.assertIn(f"`{o}/y` (candidate)", report)
        self.assertIn("grouped by header name only and may differ", report)

    def test_two_schemes_of_one_host_are_two_issues(self):
        # The store keeps both schemes under one host, so one export reads all four rows.
        for origin in ("http://shop.test", "https://shop.test"):
            self.legacy_confirmed(origin + "/a", "Missing Content-Security-Policy")
            self.claim(origin + "/b", "Missing Content-Security-Policy header")
        self.assertEqual(len(self.rows("http://shop.test")), 4)
        csp = self.issues("http://shop.test", "csp")
        self.assertEqual(sorted(sorted(i["affected_instances"]) for i in csp),
                         [["http://shop.test/a", "http://shop.test/b"],
                          ["https://shop.test/a", "https://shop.test/b"]], _dump(csp))

    def test_header_class_without_recorded_value_gets_the_header_name_key_and_note(self):
        o = self.ORIGIN
        self.claim(o + "/a", "Missing Strict-Transport-Security header")
        self.claim(o + "/b", "missing HSTS header")
        self.claim(o + "/c", "Missing X-Content-Type-Options header")     # another header
        self.claim(o + "/d", "missing security headers")                 # no header named
        self.claim(o + "/e", "Missing security headers")
        grouped = {tuple(i["affected_routes"]): i for i in self.issues(o, "missing_headers")}
        self.assertEqual(set(grouped), {("/a", "/b"), ("/c",), ("/d", "/e")}, _dump(grouped))
        hsts = grouped[("/a", "/b")]
        self.assertEqual(hsts["header_policy"], {"headers": ["strict-transport-security"], "recorded": False,
                                                 "observed": {}})
        self.assertTrue(any("may differ" in line for line in hsts["limitations"]))
        self.assertEqual(grouped[("/c",)]["header_policy"]["headers"], ["x-content-type-options"])
        # A label naming no header keeps E2's host-wide key, so its issue id is unchanged.
        unnamed = [r for r in self.rows(o) if r["url"] in (o + "/d", o + "/e")]
        self.assertEqual({issues.issue_key(r) for r in unnamed},
                         {issues.issue_key(r, recorded_policy=False) for r in unnamed})
        self.assertEqual(grouped[("/d", "/e")]["issue_id"],
                         issues.issue_id_for(issues.issue_key(unnamed[0], recorded_policy=False)))
        report = self.report(o)
        self.assertIn("one header name (strict-transport-security)", report)


class OtherClassesStayPerRouteTests(_HeaderCase):
    ORIGIN = "http://shop.test"

    def test_idor_and_other_classes_keep_their_per_route_issues(self):
        o = self.ORIGIN
        # Header text in their evidence must not pull other classes into a header issue.
        header_text = ("Content-Security-Policy: absent | Content-Security-Policy-Report-Only: absent "
                       "| X-Frame-Options: absent | X-Content-Type-Options is missing")
        routes = ("/api/orders/1", "/api/users/2", "/api/invoices/3")
        for cls in ("idor", "sqli", "jwt", "info_disclosure"):
            for route in routes:
                self.claim(o + route, cls, agent="csp_validator", evidence=header_text)
        rows = self.rows(o)
        self.assertEqual(len(rows), 12)
        for row in rows:
            self.assertIsNone(issues.header_policy(row), row["vulnerability_class"])
            self.assertEqual(issues.issue_key(row), issues.issue_key(row, recorded_policy=False))
        exported = self.issues(o)
        self.assertFalse([i for i in exported if "header_policy" in i or "route_status" in i], _dump(exported))
        idor = self.issues(o, "idor")
        self.assertEqual(sorted(i["endpoint_family"] for i in idor),
                         ["/api/invoices/{id}", "/api/orders/{id}", "/api/users/{id}"], _dump(idor))
        self.assertTrue(all(i["instances_count"] == 1 for i in idor))


if __name__ == "__main__":
    unittest.main()
