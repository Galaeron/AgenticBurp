"""Ticket E2: host-level facts are computed once per run and grouped as host issues.

- Recon: a host is crawled once per identity per run; later plans decide their own
  claim from the first crawl (0 requests).
- Header audit: the universal header audit records each route template and identity
  it checked in the run's execution registry, so the model-review path sends nothing
  for a template the audit already fetched.
- Issues: csp/cors findings group by host + class + header fingerprint.

Every positive case has a control that removes the new logic (no registry, the
registry method patched out, the grouping set emptied). The target is an owned
127.0.0.1 server that counts what it is sent.
"""
from __future__ import annotations

import asyncio
import functools
import http.server
import json
import threading
import unittest
from collections import Counter
from unittest.mock import patch

from harness import issues
from harness.categories import canonicalize
from harness.engagement import EngagementState
from harness.execution_registry import ExecutionRegistry, execution_key
from harness.models import AgentReport, Finding, HttpExchange
from harness.orchestrator_helpers import universal_header_audit
from harness.run_context import RunContext, ScopePolicy
from harness.test_confirmation_soundness_rve import _CallerBase, _finding
from harness.validators.base import header_fingerprint
from harness.validators.cors_validator import CorsValidator
from harness.validators.csp_validator import CspValidator
from harness.validators.recon_validator import ReconValidator

HOSTS = ["127.0.0.1"]
_HTML = "<html><head><title>t</title></head><body><a href='/shop/items/2'>x</a></body></html>"


class _Site:
    """Loopback site. `headers_for(path)` gives a page's response headers;
    `cors_for(path)` is None, "reflect" or "reflect+vary". Every request is logged
    as (path, has Origin, Cookie)."""

    def __init__(self, headers_for=None, cors_for=None, tech="Apache/2.4.41"):
        log = self.log = []
        headers_for = headers_for or (lambda path: {})
        cors_for = cors_for or (lambda path: None)

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                path = self.path.split("?", 1)[0]
                log.append((path, self.headers.get("Origin"), self.headers.get("Cookie")))
                body = _HTML.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Server", tech)
                for name, value in headers_for(path).items():
                    self.send_header(name, value)
                mode, origin = cors_for(path), self.headers.get("Origin")
                if mode and origin:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    if mode == "reflect+vary":
                        self.send_header("Vary", "Origin")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_OPTIONS = do_GET

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.origin = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)

    @property
    def requests(self) -> int:
        return len(self.log)

    def fetches_of(self, path: str) -> int:
        return sum(1 for p, origin, _ in self.log if p == path and origin is None)


def _page(site, path, headers=None) -> HttpExchange:
    return HttpExchange(url=site.origin + path, method="GET", request_headers=dict(headers or {}),
                        response_status=200, response_headers={"Content-Type": "text/html"},
                        response_body=_HTML)


def _claim(cls: str) -> Finding:
    return Finding(vulnerability_class=cls, confidence=0.5, summary="candidate",
                   evidence="fixture", suggested_test="verify", basis="derived")


# --------------------------------------------------------------------------- #
# Recon: once per host and identity
# --------------------------------------------------------------------------- #

class ReconOncePerHostTests(unittest.TestCase):
    def setUp(self):
        self.site = _Site()
        self.addCleanup(self.site.close)

    def _plans(self, plans, *, registry=True):
        """Validate each (finding class, exchange) in one run; returns the results."""
        async def go():
            async with RunContext.create(allowed_hosts=HOSTS, max_requests=2000) as run:
                if registry:
                    run.execution_registry = ExecutionRegistry(budget=run.budget)
                run.sessions.register("bob", "user", {"Cookie": "sid=bob"}, name="bob",
                                      allowed_origins=[ScopePolicy.origin_of(self.site.origin)])
                validator = ReconValidator(run_context=run, allowed_hosts=HOSTS)
                results, counts = [], []
                for cls, exchange in plans:
                    results.append(await validator.validate(_claim(cls), exchange))
                    counts.append(self.site.requests)
                return results, counts, getattr(run, "execution_registry", None)
        return asyncio.run(go())

    def test_second_plan_on_the_same_host_and_identity_sends_nothing(self):
        plans = [("technology fingerprint", _page(self.site, "/shop/items/1?a=1")),
                 ("sensitive endpoint exposure", _page(self.site, "/about?b=2"))]
        (first, second), (after_first, after_second), registry = self._plans(plans)
        self.assertGreater(after_first, 20)                     # the crawl: host-level paths
        self.assertEqual(after_second, after_first + 1)         # only its own start page
        # Each plan decides its own claim from the map.
        self.assertEqual((first.status, second.status), ("confirmed", "not_confirmed"))
        self.assertIn("technologies", first.summary)
        self.assertIn("0 sensitive endpoints", second.summary)
        self.assertNotIn("recon reused", first.evidence)
        self.assertIn(f"recon reused from first crawl of {self.site.origin}", second.evidence)
        self.assertEqual(registry.stats()["by_validator"]["recon_validator"]["hits"], 1)

    def test_a_later_plan_sees_its_own_exchange_in_the_reused_map(self):
        plans = [("technology fingerprint", _page(self.site, "/shop/items/1?a=1")),
                 ("parameter discovery", _page(self.site, "/about?only_here=2"))]
        (_, second), (after_first, after_second), _ = self._plans(plans)
        self.assertEqual(after_second, after_first + 1)         # only its own start page
        self.assertEqual(second.status, "confirmed")
        self.assertIn("only_here", second.evidence)             # its own parameter, no new send

    def test_a_different_identity_crawls_again(self):
        plans = [("technology fingerprint", _page(self.site, "/shop/items/1")),
                 ("technology fingerprint", _page(self.site, "/shop/items/1", {"Cookie": "sid=bob"}))]
        _, (after_first, after_second), _ = self._plans(plans)
        self.assertGreater(after_second, after_first + 20)

    def test_control_without_the_registry_crawls_for_every_plan(self):
        plans = [("technology fingerprint", _page(self.site, "/shop/items/1")),
                 ("sensitive endpoint exposure", _page(self.site, "/about"))]
        (first, second), (after_first, after_second), _ = self._plans(plans, registry=False)
        self.assertEqual(after_second, 2 * after_first)
        self.assertNotIn("recon reused", second.evidence)

    def test_control_patching_the_memo_out_crawls_for_every_plan(self):
        async def run_it(self_registry, key, coro_fn, *, name="memo"):
            return await coro_fn(), False
        plans = [("technology fingerprint", _page(self.site, "/shop/items/1")),
                 ("sensitive endpoint exposure", _page(self.site, "/about"))]
        with patch.object(ExecutionRegistry, "memo", run_it):
            _, (after_first, after_second), _ = self._plans(plans)
        self.assertEqual(after_second, 2 * after_first)

    def test_concurrent_plans_share_one_crawl(self):
        async def go():
            async with RunContext.create(allowed_hosts=HOSTS, max_requests=2000) as run:
                run.execution_registry = ExecutionRegistry(budget=run.budget)
                first = ReconValidator(run_context=run, allowed_hosts=HOSTS)
                second = ReconValidator(run_context=run, allowed_hosts=HOSTS)
                await asyncio.gather(
                    first.validate(_claim("technology fingerprint"), _page(self.site, "/shop/items/1")),
                    second.validate(_claim("sensitive endpoint exposure"), _page(self.site, "/about")))
                return run.execution_registry.stats()["by_validator"]["recon_validator"]
        stats = asyncio.run(go())
        self.assertEqual((stats["misses"], stats["hits"], stats["inflight_joins"]), (1, 1, 1))


# --------------------------------------------------------------------------- #
# Header audit: checked once per route template and identity
# --------------------------------------------------------------------------- #

class ReconStartPageTests(unittest.TestCase):
    """A reused crawl still follows the later plan's own start page: the first crawl
    began elsewhere and never reached what only that page links to."""
    PAGES = {
        "/api/data": ("application/json", '{"ok": true}'),
        "/home": ("text/html", "<html><body><a href='/level1'>l</a></body></html>"),
        "/level1": ("text/html", "<html><body><a href='/search?deep_secret_param=1'>s</a></body></html>"),
    }

    def setUp(self):
        pages, log = self.PAGES, []
        self.log = log

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                path = self.path.split("?", 1)[0]
                log.append(path)
                ctype, body = pages.get(path, ("text/html", "<html></html>"))
                data = body.encode()
                self.send_response(200 if path in pages else 404)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.origin = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def _exchange(self, path):
        ctype, body = self.PAGES[path]
        return HttpExchange(url=self.origin + path, method="GET", request_headers={},
                            response_status=200, response_headers={"Content-Type": ctype},
                            response_body=body)

    def _two_plans(self, *, registry):
        async def go():
            async with RunContext.create(allowed_hosts=HOSTS, max_requests=2000) as run:
                if registry:
                    run.execution_registry = ExecutionRegistry(budget=run.budget)
                validator = ReconValidator(run_context=run, allowed_hosts=HOSTS)
                await validator.validate(_claim("technology fingerprint"), self._exchange("/api/data"))
                second = await validator.validate(_claim("parameter discovery"), self._exchange("/home"))
                return second, getattr(run, "execution_registry", None)
        return asyncio.run(go())

    def test_a_reused_crawl_follows_the_later_plans_start_page(self):
        second, registry = self._two_plans(registry=True)
        self.assertEqual(registry.stats()["by_validator"]["recon_validator"]["hits"], 1)
        self.assertIn("/level1", self.log)
        self.assertEqual(second.status, "confirmed")
        self.assertIn("deep_secret_param", second.evidence + second.summary)

    def test_control_without_the_registry_the_same_page_is_found(self):
        second, _ = self._two_plans(registry=False)
        self.assertEqual(second.status, "confirmed")
        self.assertIn("deep_secret_param", second.evidence + second.summary)

    def test_control_patching_the_follow_crawl_out_loses_the_page(self):
        crawl = ReconValidator._crawl

        async def first_crawl_only(validator, base_url, url, depth, max_depth, result):
            if url.endswith("/home") and depth == 0 and validator.visited_urls:
                return
            await crawl(validator, base_url, url, depth, max_depth, result)
        with patch.object(ReconValidator, "_crawl", first_crawl_only):
            second, _ = self._two_plans(registry=True)
        self.assertNotIn("/level1", self.log)
        self.assertEqual(second.status, "not_confirmed")


class BlankFingerprintIssueTests(unittest.TestCase):
    def _grouped(self, fingerprint=None):
        rows = [{"vulnerability_class": "cors", "url": "http://shop.test/api/a", "method": "GET",
                 "confirmed": True, "severity": "medium", "summary": "confirmed"},
                {"vulnerability_class": "permissive cors", "url": "http://shop.test/api/b",
                 "method": "POST", "confirmed": False, "severity": "medium", "summary": "candidate"}]
        if fingerprint:
            for row in rows:
                row["header_fingerprint"] = fingerprint
        return issues.group_findings_into_issues(rows)

    def test_findings_without_a_fingerprint_are_not_one_host_issue(self):
        grouped = self._grouped()
        self.assertEqual(len(grouped), 2)
        self.assertEqual(sum(1 for issue in grouped if issue.confirmed), 1)

    def test_control_one_fingerprint_makes_one_issue(self):
        self.assertEqual(len(self._grouped("acao=*")), 1)


class _AuditBase(_CallerBase, unittest.TestCase):
    def _setup(self, site, validators):
        self.site = site
        self.addCleanup(site.close)
        orch = self._orch(hosts=("127.0.0.1",))
        orch.validator_registry.validators = validators
        orch.validator_registry.active_enabled = True
        return orch

    def _both(self, orch, audited, reviewed, *, registry=True, review_class="csp",
              sessions=(), audit_extra=None):
        """The universal header audit over `audited` exchanges, then the model-review
        path over `reviewed`, in one run. Returns (state, reports per review, fetch
        counts after the audit and after the review)."""
        async def go():
            async with RunContext.create(allowed_hosts=HOSTS, max_requests=4000,
                                         gate_config={"active_enabled": True}) as run:
                if registry:
                    run.execution_registry = ExecutionRegistry(budget=run.budget)
                for name, cookie in sessions:
                    run.sessions.register(name, "user", {"Cookie": cookie}, name=name,
                                          allowed_origins=[ScopePolicy.origin_of(self.site.origin)])
                state = EngagementState(host=self.site.origin)
                await universal_header_audit(orch, state, audited, run_context=run)
                after_audit = self.site.requests
                reports = []
                for exchange in reviewed:
                    got, _proofs = await orch._validate_findings(
                        exchange, [AgentReport(agent="csp", model="fake",
                                               findings=[_finding(review_class)])], run_context=run)
                    reports.extend(got)
                return state, reports, after_audit, self.site.requests
        return asyncio.run(go())


class HeaderAuditReuseTests(_AuditBase):
    def _csp(self, site):
        return self._setup(site, {"csp": CspValidator(allowed_hosts=HOSTS)})

    def test_review_of_an_audited_template_fetches_nothing(self):
        site = _Site()
        orch = self._csp(site)
        # items/1 was audited; items/2 is the same route template.
        state, reports, after_audit, after_review = self._both(
            orch, [_page(site, "/shop/items/1")], [_page(site, "/shop/items/2")])
        self.assertEqual(after_audit, 1)                         # both classes from one fetch
        self.assertEqual(after_review, 1)                        # the review sent nothing
        self.assertEqual(len(reports), 1)
        self.assertTrue(reports[0].summary.startswith("covered by header-audit:"), reports[0].summary)
        self.assertFalse(reports[0].confirmed)

    def test_the_framing_claim_is_covered_by_the_same_audit(self):
        site = _Site()
        orch = self._csp(site)
        _, reports, after_audit, after_review = self._both(
            orch, [_page(site, "/shop/items/1")], [_page(site, "/shop/items/2")],
            review_class="clickjacking")
        self.assertEqual((after_audit, after_review), (1, 1))
        self.assertTrue(reports[0].summary.startswith("covered by header-audit:"))

    def test_a_template_the_audit_never_saw_is_fetched(self):
        site = _Site()
        orch = self._csp(site)
        _, reports, after_audit, after_review = self._both(
            orch, [_page(site, "/shop/items/1")], [_page(site, "/other/page")])
        self.assertEqual((after_audit, after_review), (1, 2))
        self.assertTrue(reports[0].confirmed)                    # the review ran its own check

    def test_a_second_identity_is_fetched_again(self):
        site = _Site()
        orch = self._csp(site)
        _, reports, after_audit, after_review = self._both(
            orch, [_page(site, "/shop/items/1", {"Cookie": "sid=alice"})],
            [_page(site, "/shop/items/2", {"Cookie": "sid=bob"})],
            sessions=[("alice", "sid=alice"), ("bob", "sid=bob")])
        self.assertEqual((after_audit, after_review), (1, 2))
        self.assertTrue(reports[0].confirmed)
        self.assertEqual([c for _, _, c in site.log], ["sid=alice", "sid=bob"])

    def test_the_same_identity_is_covered(self):
        site = _Site()
        orch = self._csp(site)
        _, reports, after_audit, after_review = self._both(
            orch, [_page(site, "/shop/items/1", {"Cookie": "sid=alice"})],
            [_page(site, "/shop/items/2", {"Cookie": "sid=alice"})],
            sessions=[("alice", "sid=alice")])
        self.assertEqual((after_audit, after_review), (1, 1))

    def test_control_without_a_registry_fetches_for_the_review_too(self):
        site = _Site()
        orch = self._csp(site)
        _, reports, after_audit, after_review = self._both(
            orch, [_page(site, "/shop/items/1")], [_page(site, "/shop/items/2")], registry=False)
        self.assertEqual((after_audit, after_review), (1, 2))
        self.assertTrue(reports[0].confirmed)

    def test_control_patching_the_audit_routing_out_fetches_for_the_review_too(self):
        async def pass_through(self_registry, validator, exchange, classes, *, case_ref, call):
            return await call()
        site = _Site()
        orch = self._csp(site)
        with patch.object(ExecutionRegistry, "run_audit", pass_through):
            _, reports, after_audit, after_review = self._both(
                orch, [_page(site, "/shop/items/1")], [_page(site, "/shop/items/2")])
        self.assertEqual((after_audit, after_review), (1, 2))

    def test_cors_review_of_an_audited_template_sends_no_probe(self):
        site = _Site(cors_for=lambda path: "reflect")
        orch = self._setup(site, {"cors": CorsValidator(allowed_hosts=HOSTS)})
        _, reports, after_audit, after_review = self._both(
            orch, [_page(site, "/api/items/1")], [_page(site, "/api/items/2")], review_class="cors")
        self.assertGreater(after_audit, 0)
        self.assertEqual(after_review, after_audit)
        self.assertTrue(reports[0].summary.startswith("covered by header-audit:"))

    def test_cors_control_without_a_registry_probes_again(self):
        site = _Site(cors_for=lambda path: "reflect")
        orch = self._setup(site, {"cors": CorsValidator(allowed_hosts=HOSTS)})
        _, reports, after_audit, after_review = self._both(
            orch, [_page(site, "/api/items/1")], [_page(site, "/api/items/2")],
            review_class="cors", registry=False)
        self.assertGreater(after_review, after_audit)


class HeaderKeyTests(unittest.TestCase):
    def _key(self, validator, url, headers=None, cls="csp", method="GET", body=""):
        return execution_key(validator, HttpExchange(url=url, method=method, request_body=body,
                                                     request_headers=dict(headers or {})), cls)

    def test_the_key_is_the_route_template_not_the_parameters_or_body(self):
        for name in ("csp_validator", "cors_validator"):
            a = self._key(name, "http://h/shop/items/1?x=1")
            self.assertEqual(a, self._key(name, "http://h/shop/items/2?y=2"))
            self.assertEqual(a, self._key(name, "http://h/shop/items/3", body='{"z": 1}'))
            self.assertNotEqual(a, self._key(name, "http://h/shop/items/1", method="POST"))
            self.assertNotEqual(a, self._key(name, "http://h/other"))
            self.assertNotEqual(a, self._key(name, "http://h/shop/items/1", {"Cookie": "sid=b"}))
            self.assertNotEqual(a, self._key(name, "http://other/shop/items/1"))

    def test_csp_and_framing_claims_are_different_checks_but_cors_ignores_the_class(self):
        self.assertNotEqual(self._key("csp_validator", "http://h/p", cls="csp"),
                            self._key("csp_validator", "http://h/p", cls="clickjacking"))
        self.assertEqual(self._key("csp_validator", "http://h/p", cls="Content Security Policy"),
                         self._key("csp_validator", "http://h/p", cls="csp"))
        self.assertEqual(self._key("cors_validator", "http://h/p", cls="cors"),
                         self._key("cors_validator", "http://h/p", cls="cors misconfiguration"))


# --------------------------------------------------------------------------- #
# Fingerprints reach the findings; findings group by host policy
# --------------------------------------------------------------------------- #

class HostPolicyIssueCallerTests(_AuditBase):
    """Findings the real audit produces, grouped by the real issue code."""

    def _issues(self, state):
        """The state's findings as the store would hand them to the report (url and
        method of the endpoint they were attached to), and their issues."""
        findings = []
        for key, ep in state.endpoints.items():
            method, path = key.split(" ", 1)
            findings += [dict(f, url=self.site.origin + path, method=method) for f in ep.findings]
        return findings, issues.group_findings_into_issues(findings)

    def test_one_csp_policy_on_two_templates_is_one_issue_and_another_policy_is_a_second(self):
        def headers(path):
            return {"X-Frame-Options": "DENY"} if path == "/pages/b" else {}
        site = _Site(headers_for=headers)
        orch = self._setup(site, {"csp": CspValidator(allowed_hosts=HOSTS)})
        audited = [_page(site, p) for p in ("/shop/items/1", "/shop/items/2", "/pages/a", "/pages/b")]
        state, _, after_audit, _ = self._both(orch, audited, [])
        self.assertEqual(after_audit, 3)                         # items/2 shares items/1's template
        findings, grouped = self._issues(state)
        self.assertEqual({f["header_fingerprint"] for f in findings} - {""},
                         {header_fingerprint(None, None, None), header_fingerprint(None, None, "DENY")})
        self.assertEqual(len(grouped), 2, [(i.vulnerability_class, i.host) for i in grouped])
        bare = next(i for i in grouped if "/pages/a" in "".join(i.affected_instances))
        export = issues.export_issue(bare)
        self.assertEqual(export["affected_routes"], ["/pages/a", "/shop/items/{id}"])
        self.assertEqual(export["vulnerability_class"], "csp")

    def test_control_without_the_host_grouping_is_one_issue_per_route(self):
        site = _Site()
        orch = self._setup(site, {"csp": CspValidator(allowed_hosts=HOSTS)})
        state, *_ = self._both(orch, [_page(site, p) for p in ("/pages/a", "/pages/c")], [])
        with patch.object(issues, "_HEADER_POLICY_CLASSES", frozenset()):
            _, grouped = self._issues(state)
        self.assertEqual(len(grouped), 2)                        # one per route
        _, grouped = self._issues(state)
        self.assertEqual(len(grouped), 1)

    def test_cors_policies_that_differ_in_vary_are_two_issues(self):
        policy = {"/api/a": "reflect+vary", "/api/b": "reflect", "/api/c": "reflect+vary"}
        site = _Site(cors_for=policy.get)
        orch = self._setup(site, {"cors": CorsValidator(allowed_hosts=HOSTS)})
        state, *_ = self._both(orch, [_page(site, p) for p in policy], [])
        findings, grouped = self._issues(state)
        self.assertEqual(len(findings), 3)
        self.assertEqual(sorted(len(i.members) for i in grouped), [1, 2])
        self.assertEqual({i.vulnerability_class for i in grouped}, {"cors"})


# --------------------------------------------------------------------------- #
# Issue grouping
# --------------------------------------------------------------------------- #

def _csp_finding(i, spelling, fingerprint="fp-1", cls_url="http://shop.test"):
    return {"vulnerability_class": spelling, "url": f"{cls_url}/route{i}", "method": "GET",
            "confirmed": True, "severity": "medium", "confidence": 0.8,
            "summary": "no CSP", "finding_id": f"f{i}", "header_fingerprint": fingerprint}


_SPELLINGS = ("missing CSP", "Missing Content-Security-Policy", "content security policy missing")


class HostPolicyIssueTests(unittest.TestCase):
    def test_every_spelling_canonicalizes(self):
        for spelling in ("missing csp", "missing content-security-policy",
                         "content security policy missing", "missing x-frame-options",
                         "x-frame-options missing", "clickjacking vulnerability",
                         "clickjacking exposure", "missing security headers (csp)"):
            self.assertEqual(canonicalize(spelling), "csp", spelling)
        for spelling in ("cors wildcard", "permissive cors"):
            self.assertEqual(canonicalize(spelling), "cors", spelling)
        self.assertEqual(canonicalize("csp"), "csp")                 # existing entries unchanged
        self.assertEqual(canonicalize("clickjacking"), "csp")
        self.assertIsNone(canonicalize("missing security headers"))  # still ambiguous

    def test_thirty_findings_in_three_spellings_on_thirty_routes_are_one_issue(self):
        findings = [_csp_finding(i, _SPELLINGS[i % 3]) for i in range(30)]
        grouped = issues.group_findings_into_issues(findings)
        self.assertEqual(len(grouped), 1)
        export = issues.export_issue(grouped[0])
        self.assertEqual(len(export["affected_routes"]), 30)
        self.assertEqual(export["instances_count"], 30)
        self.assertEqual(len(export["affected_instances"]), 30)
        self.assertEqual(export["vulnerability_class"], "csp")

    def test_the_issue_id_is_deterministic(self):
        a = issues.group_findings_into_issues([_csp_finding(i, "missing csp") for i in range(5)])
        b = issues.group_findings_into_issues([_csp_finding(i, "Missing CSP") for i in range(9, 4, -1)])
        self.assertEqual(a[0].issue_id, b[0].issue_id)

    def test_two_fingerprints_are_two_issues(self):
        findings = ([_csp_finding(i, "missing csp", "fp-1") for i in range(10)]
                    + [_csp_finding(i, "missing csp", "fp-2") for i in range(10, 20)])
        grouped = issues.group_findings_into_issues(findings)
        self.assertEqual(sorted(len(g.members) for g in grouped), [10, 10])

    def test_another_host_is_another_issue(self):
        findings = [_csp_finding(1, "missing csp"), _csp_finding(2, "missing csp", cls_url="http://other.test")]
        self.assertEqual(len(issues.group_findings_into_issues(findings)), 2)

    def test_an_idor_finding_still_groups_per_endpoint_family(self):
        idor = [{"vulnerability_class": "idor", "url": f"http://shop.test/route{i}/{n}",
                 "method": "GET", "confirmed": True, "severity": "high", "confidence": 0.9,
                 "summary": "foreign object", "parameter_location": "path", "parameter_name": "id"}
                for i in range(30) for n in (1, 2)]
        grouped = issues.group_findings_into_issues(idor)
        self.assertEqual(len(grouped), 30)                         # one per endpoint family
        self.assertTrue(all(len(g.members) == 2 for g in grouped))
        self.assertNotIn("affected_routes", issues.export_issue(grouped[0]))

    def test_cors_with_different_allow_origin_values_is_two_issues(self):
        def cors(i, grant):
            return {"vulnerability_class": "cors misconfiguration", "url": f"http://shop.test/api/r{i}",
                    "method": "GET", "confirmed": True, "severity": "medium", "confidence": 0.9,
                    "summary": "cors", "finding_id": f"c{i}",
                    "header_fingerprint": header_fingerprint(grant, "true", "Origin")}
        grouped = issues.group_findings_into_issues(
            [cors(1, "<reflected>"), cors(2, "https://partner.example"), cors(3, "<reflected>")])
        self.assertEqual(sorted(len(g.members) for g in grouped), [1, 2])

    def test_control_without_the_host_grouping_every_route_is_an_issue(self):
        findings = [_csp_finding(i, _SPELLINGS[i % 3]) for i in range(30)]
        with patch.object(issues, "_HEADER_POLICY_CLASSES", frozenset()):
            self.assertEqual(len(issues.group_findings_into_issues(findings)), 30)

    def test_the_nonce_does_not_split_one_policy(self):
        a = header_fingerprint("script-src 'nonce-abc123' 'self'", None, "DENY")
        b = header_fingerprint("SCRIPT-SRC  'nonce-zzz999' 'self'", None, "DENY")
        self.assertEqual(a, b)
        self.assertNotEqual(a, header_fingerprint("script-src 'self'", None, "DENY"))
        self.assertNotEqual(header_fingerprint(None, None, None), header_fingerprint("", None, None))


if __name__ == "__main__":
    unittest.main()
