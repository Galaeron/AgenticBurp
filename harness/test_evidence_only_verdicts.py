"""Evidence-only validators observe; they do not confirm (Step 2a).

A real run recorded 139 refused validation submissions and 139 "confirmed" proofs
from `csp_validator` (capability csp_clickjacking_validation) and `recon_validator`
(attack_surface_mapping): both returned confirmed=True, the store's one policy
refuses a confirmation from any capability outside its confirming set, and the
validators' own verdicts were unsound (CSP "absent" on routes that send one, CSP
claims confirmed on JSON responses, a clickjacking claim confirmed because CSP was
missing, a recon "confirmed" with 0 parameters / technologies / sensitive endpoints).

A. persistence: through Orchestrator._validate_findings with a real store, a
   confirmed result from a capability that cannot confirm is stored as an
   "observed" run (confirmed=0), without a refusal warning; a confirming capability
   still stores confirmed=1; no registry validator can produce confirmed=1 outside
   the policy.
B. csp_validator: identity replay, applicability, class-relevant checks, evidence.
C. recon_validator: the map must hold what the class claims.

The target is a function behind ``httpx.AsyncClient.request``, as in the other
caller-level validator tests, so nothing opens a socket -- except the standalone
csp_validator tests (no RunContext, so no run transport to fake), which talk to
``_Server`` fixtures bound to 127.0.0.1 only.
"""
import asyncio
import contextlib
import copy
import logging
import sqlite3
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import httpx

from harness import global_throttle, store
from harness.models import AgentReport, Finding, HttpExchange
from harness.orchestrator_helpers import universal_header_audit
from harness.run_context import RunContext, ScopePolicy
from harness.test_confirmation_soundness_rve import _CallerBase, _finding
from harness.validators.base import ValidationResult
from harness.validators.csp_validator import CspValidator
from harness.validators.recon_validator import ReconValidator
from harness.validators.sqlmap import SqlmapValidator

HOST = "shop.invalid"
BASE = f"http://{HOST}"
_HTML = {"Content-Type": "text/html; charset=utf-8"}
_ADEQUATE_CSP = "default-src 'self'; object-src 'none'; frame-ancestors 'none'"
_NO_FRAME_ANCESTORS_CSP = "default-src 'self'; object-src 'none'"
_ALICE = {"Authorization": "Bearer alice-token", "Cookie": "sid=alice-session"}


def _page(path="/dashboard", *, request_headers=None, status=200, response_headers=None):
    """A captured HTML exchange (a 200 HTML response unless told otherwise)."""
    return HttpExchange(
        url=BASE + path, method="GET", request_headers=dict(request_headers or {}),
        response_status=status,
        response_headers=dict(_HTML if response_headers is None else response_headers),
        response_body="<html></html>")


class _Target:
    """The owned app: `respond(method, url, headers)` -> (status, headers, body),
    request headers lower-cased. Every request it receives is kept."""

    def __init__(self, respond=None):
        self.respond = respond or (lambda method, url, headers: (404, {}, ""))
        self.requests = []

    def patched(self):
        target = self

        async def fake_request(client, method, url, **kwargs):
            headers = {k.lower(): v for k, v in (kwargs.get("headers") or {}).items()}
            target.requests.append((method, str(url), headers))
            status, response_headers, body = target.respond(method, str(url), headers)
            return httpx.Response(status, headers=response_headers, text=body,
                                  request=httpx.Request(method, url))

        return patch.object(httpx.AsyncClient, "request", fake_request)


class _Server:
    """A real owned loopback server (127.0.0.1, free port) for the standalone
    path, which uses no run transport: `respond(path, headers)` ->
    (status, headers, body), request headers lower-cased. Keeps every request."""

    def __init__(self, respond):
        self.requests = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                headers = {k.lower(): v for k, v in self.headers.items()}
                owner.requests.append((self.path, headers))
                status, response_headers, body = respond(self.path, headers)
                data = body.encode()
                self.send_response(status)
                for name, value in response_headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def url(self, path="/"):
        return f"http://127.0.0.1:{self.port}{path}"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def _serving(headers, status=200):
    """A target whose every URL answers with these response headers."""
    return _Target(lambda method, url, request_headers: (status, headers, "<html></html>"))


def _runs():
    """(capability, status, confirmed, summary) of every stored validation run."""
    conn = sqlite3.connect(str(store._DB_PATH))
    try:
        return conn.execute(
            """SELECT tp.capability, vr.status, vr.confirmed, vr.summary
               FROM validation_runs vr JOIN test_plans tp ON tp.plan_id = vr.plan_id
               ORDER BY vr.id""").fetchall()
    finally:
        conn.close()


class _Warnings(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


@contextlib.contextmanager
def _warnings_logged():
    handler, root = _Warnings(), logging.getLogger()
    root.addHandler(handler)
    try:
        yield handler.messages
    finally:
        root.removeHandler(handler)


class _ConfirmingSqlmap(SqlmapValidator):
    """The real sqlmap leg's name, classes and plan (capability
    sql_injection_validation); only the tool run is replaced by a confirmation."""

    async def validate(self, finding, exchange):
        return ValidationResult(
            validator=self.name, status="confirmed", finding_class=finding.vulnerability_class,
            confidence=0.95, confirmed=True, summary="boolean differential",
            evidence="true/false responses differed")


class _Caller(_CallerBase, unittest.TestCase):
    def _dispatch(self, key, validator, finding, exchange, target=None, *, sessions=None):
        """One validator through the production caller, inside an entered run.
        Returns (reports, proofs, target)."""
        orch = self._orch(hosts=(HOST,))
        orch.validator_registry.validators = {key: validator}
        target = target or _Target()

        async def go():
            async with RunContext.create(allowed_hosts=[HOST], max_requests=200,
                                         gate_config={"active_enabled": True}) as run:
                for session_id, headers in (sessions or {}).items():
                    run.sessions.register(session_id, session_id, headers,
                                          allowed_origins=[ScopePolicy.origin_of(exchange.url)])
                return await orch._validate_findings(
                    exchange, [AgentReport(agent=key, model="fake", findings=[finding])],
                    run_context=run)

        with target.patched():
            reports, proofs = asyncio.run(go())
        self.assertTrue(reports, "the validator was not dispatched")
        return reports, proofs, target

    def _csp(self, claim, exchange, target, **kwargs):
        reports, _proofs, target = self._dispatch(
            "csp", CspValidator(allowed_hosts=[HOST]), _finding(claim), exchange, target, **kwargs)
        self.assertEqual(len(reports), 1)
        return reports[0], target


# ---------------------------------------------------------------- A. persistence
class ObservedPersistenceTests(_Caller):
    def test_csp_confirmation_is_stored_as_an_observation_without_a_refusal(self):
        target = _serving(_HTML)  # no CSP: a genuine, confirmed claim
        with _warnings_logged() as warnings:
            reports, proofs, _ = self._dispatch(
                "csp", CspValidator(allowed_hosts=[HOST]), _finding("csp"), _page(), target)
        self.assertEqual([m for m in warnings if "failed to persist" in m], [], warnings)
        self.assertEqual(
            [(cap, status, confirmed) for cap, status, confirmed, _ in _runs()],
            [("csp_clickjacking_validation", "observed", 0)])
        self.assertTrue(_runs()[0][3].startswith("observation: "), _runs()[0][3])
        # The proof record and the report are unchanged for these validators.
        self.assertTrue(reports[0].confirmed)
        self.assertEqual(reports[0].status, "confirmed")
        self.assertEqual([p["verdict"] for p in proofs], ["confirmed"])

    def test_recon_confirmation_is_stored_as_an_observation_without_a_refusal(self):
        exchange = _page("/api/me", request_headers=_ALICE)  # a credentialed route is a sensitive endpoint
        with _warnings_logged() as warnings:
            reports, proofs, _ = self._dispatch(
                "recon", ReconValidator(allowed_hosts=[HOST], max_depth=0),
                _finding("attack surface mapping"), exchange, _Target())
        self.assertEqual([m for m in warnings if "failed to persist" in m], [], warnings)
        self.assertEqual(
            [(cap, status, confirmed) for cap, status, confirmed, _ in _runs()],
            [("attack_surface_mapping", "observed", 0)])
        self.assertEqual((reports[0].status, reports[0].confirmed), ("confirmed", True))
        self.assertEqual([p["verdict"] for p in proofs], ["confirmed"])

    def test_defect_injection_old_submission_is_refused_and_warns(self):
        # Make the orchestrator believe csp can confirm while the store keeps
        # its policy: this is the old behaviour, and it must be visible both as
        # the refusal warning and as a missing run (so the checks above bite).
        class _OldPolicy:
            def __getattr__(self, name):
                return getattr(store, name)

            @staticmethod
            def capability_can_confirm(capability):
                return True

        with patch("harness.orchestrator_confirm.store", _OldPolicy()), _warnings_logged() as warnings:
            self._dispatch("csp", CspValidator(allowed_hosts=[HOST]), _finding("csp"),
                           _page(), _serving(_HTML))
        self.assertTrue([m for m in warnings if "cannot mark the vulnerability confirmed" in m], warnings)
        self.assertEqual(_runs(), [])

    def test_confirming_capability_still_stores_a_confirmation(self):
        exchange = _page("/search?q=1")
        reports, _proofs, _ = self._dispatch(
            "sqlmap", _ConfirmingSqlmap(allowed_hosts=[HOST]), _finding("sqli"), exchange)
        self.assertTrue(reports[0].confirmed)
        rows = _runs()
        self.assertEqual([(cap, status, confirmed) for cap, status, confirmed, _ in rows],
                         [("sql_injection_validation", "confirmed", 1)])
        self.assertFalse(rows[0][3].startswith("observation:"), rows[0][3])

    def test_observed_run_is_neither_confirmed_nor_refuted_in_the_coverage_ledger(self):
        self._dispatch("csp", CspValidator(allowed_hosts=[HOST]), _finding("csp"),
                       _page(), _serving(_HTML))
        self._dispatch("sqlmap", _ConfirmingSqlmap(allowed_hosts=[HOST]), _finding("sqli"),
                       _page("/search?q=1"))
        ledger = {row["category"]: row["status"] for row in store.coverage_report(HOST)}
        self.assertEqual(ledger["csp"], "supported")        # evidence, not a confirmation
        self.assertEqual(ledger["sqli"], "confirmed")       # negative control

    def test_store_keeps_one_policy(self):
        self.assertFalse(store.capability_can_confirm("csp_clickjacking_validation"))
        self.assertFalse(store.capability_can_confirm("attack_surface_mapping"))
        self.assertTrue(store.capability_can_confirm("sql_injection_validation"))
        validator = CspValidator(allowed_hosts=[HOST])
        exchange = _page()
        plan = validator.plan(_finding("csp"), exchange)
        store.persist_test_plans(exchange, [plan])
        from harness.models import ValidationSubmission
        submission = dict(plan_id=plan.id, confidence=0.9, summary="s", evidence="e",
                          executor=f"{plan.execution_plane}:{plan.capability}",
                          source_exchange_hash=plan.source_exchange_hash)
        refused, reason = store.persist_validation_submission(
            ValidationSubmission(status="confirmed", confirmed=True, **submission))
        self.assertFalse(refused)
        self.assertIn("cannot mark the vulnerability confirmed", reason)
        accepted, _ = store.persist_validation_submission(
            ValidationSubmission(status="observed", confirmed=False, **submission))
        self.assertTrue(accepted)

    def test_no_registry_validator_stores_a_confirmation_outside_the_policy(self):
        orch = self._orch(hosts=(HOST,))
        registry = orch.validator_registry
        covered = {}
        for key, validator in list(registry.validators.items()):
            finding = Finding(vulnerability_class=sorted(validator.finding_classes)[0],
                              confidence=0.5, summary="candidate", evidence="fixture",
                              suggested_test="verify", basis="derived")
            exchange = _page(f"/items?id=1&via={key}")
            if validator.plan(finding, exchange) is None:
                continue  # no plan, nothing is submitted to the store

            async def forced(self, finding, exchange):
                return ValidationResult(
                    validator=self.name, status="confirmed",
                    finding_class=finding.vulnerability_class, confidence=0.9, confirmed=True,
                    summary="forced confirmation", evidence="forced")

            confirming = copy.copy(validator)
            confirming.__class__ = type("Forced" + type(validator).__name__,
                                        (type(validator),), {"validate": forced})
            with patch.object(registry, "for_finding", lambda f, e, agent=None: [confirming]):
                async def go():
                    async with RunContext.create(allowed_hosts=[HOST], max_requests=50,
                                                 gate_config={"active_enabled": True}) as run:
                        return await orch._validate_findings(
                            exchange, [AgentReport(agent="", model="fake", findings=[finding])],
                            run_context=run)
                asyncio.run(go())
            covered[key] = validator.plan(finding, exchange).capability
        runs = {}
        for capability, status, confirmed, _summary in _runs():
            runs.setdefault(capability, set()).add((status, confirmed))
        # Not vacuous: both kinds of capability were exercised, csp and recon among them.
        self.assertIn("csp_clickjacking_validation", runs)
        self.assertIn("attack_surface_mapping", runs)
        self.assertIn("sql_injection_validation", runs)
        self.assertEqual(set(covered.values()), set(runs), "a validator's confirmed result was not stored")
        for capability, outcomes in runs.items():
            expected = {("confirmed", 1)} if store.capability_can_confirm(capability) else {("observed", 0)}
            self.assertEqual(outcomes, expected, capability)


# ------------------------------------------------------------------ B. csp_validator
class CspVerdictTests(_Caller):
    def test_html_without_csp_is_a_confirmed_csp_claim(self):
        report, target = self._csp("csp", _page(), _serving(_HTML))
        self.assertEqual((report.status, report.confirmed), ("confirmed", True))
        self.assertIn("No Content-Security-Policy header present", report.summary)
        for observed in ("URL: http://shop.invalid/dashboard", "HTTP 200 text/html", "source: fresh",
                         "Content-Security-Policy: absent",
                         "Content-Security-Policy-Report-Only: absent", "X-Frame-Options: absent"):
            self.assertIn(observed, report.evidence)
        self.assertEqual([r[0] for r in target.requests], ["GET"])

    def test_html_with_an_adequate_csp_is_not_confirmed_and_states_the_policy(self):
        report, _ = self._csp("csp", _page(), _serving({**_HTML, "Content-Security-Policy": _ADEQUATE_CSP,
                                                         "X-Frame-Options": "DENY"}))
        self.assertEqual((report.status, report.confirmed), ("not_confirmed", False))
        self.assertIn(f"Content-Security-Policy: {_ADEQUATE_CSP}", report.evidence)
        self.assertIn("X-Frame-Options: DENY", report.evidence)
        self.assertNotIn("No Content-Security-Policy header present", report.summary + report.evidence)

    def test_header_values_in_evidence_are_bounded(self):
        policy = "default-src 'self'; object-src 'none'; img-src " + " ".join(
            f"https://cdn{n}.example.com" for n in range(40))
        self.assertGreater(len(policy), 600)
        report, _ = self._csp("csp", _page(), _serving({**_HTML, "Content-Security-Policy": policy}))
        self.assertIn(policy[:300] + "...", report.evidence)
        self.assertNotIn(policy[:301], report.evidence)

    def test_report_only_policy_is_stated_and_not_taken_for_an_enforced_one(self):
        report, _ = self._csp("csp", _page(), _serving({
            **_HTML, "Content-Security-Policy-Report-Only": _ADEQUATE_CSP}))
        self.assertTrue(report.confirmed)
        self.assertIn("Content-Security-Policy: absent", report.evidence)
        self.assertIn(f"Content-Security-Policy-Report-Only: {_ADEQUATE_CSP}", report.evidence)

    def test_json_response_is_not_applicable(self):
        exchange = _page("/api/items", response_headers={"Content-Type": "application/json"})
        report, _ = self._csp("csp", exchange, _serving({"Content-Type": "application/json"}))
        self.assertEqual((report.status, report.confirmed), ("skipped", False))
        self.assertEqual(
            report.summary,
            "not applicable: HTTP 200 application/json; CSP/framing protect HTML documents")
        self.assertIn("HTTP 200 application/json", report.evidence)

    def test_xhtml_response_is_evaluated(self):
        xhtml = {"Content-Type": "application/xhtml+xml"}
        report, _ = self._csp("csp", _page(response_headers=xhtml), _serving(xhtml))
        self.assertEqual((report.status, report.confirmed), ("confirmed", True))

    def test_error_page_is_inconclusive_and_never_a_missing_header_claim(self):
        report, _ = self._csp("csp", _page(), _serving(_HTML, status=500))
        self.assertEqual((report.status, report.confirmed), ("skipped", False))
        self.assertTrue(report.summary.startswith("inconclusive: HTTP 500"), report.summary)

    def test_client_error_page_is_not_applicable(self):
        report, _ = self._csp("csp", _page(), _serving(_HTML, status=404))
        self.assertEqual((report.status, report.confirmed), ("skipped", False))
        self.assertTrue(report.summary.startswith("not applicable: HTTP 404 text/html"), report.summary)

    def test_redirect_to_another_route_is_inconclusive_never_a_verdict(self):
        # An expired session sends the route to /login, a CSP-less HTML page: that
        # page's headers say nothing about the route.
        def app(method, url, headers):
            if url.endswith("/dashboard"):
                return 302, {"Location": "/login?next=/dashboard&token=SECRET123"}, ""
            return 200, _HTML, "<html>sign in</html>"

        for claim in ("csp", "clickjacking"):
            with self.subTest(claim=claim):
                report, target = self._csp(claim, _page(), _Target(app))
                self.assertEqual((report.status, report.confirmed), ("skipped", False))
                self.assertNotEqual(report.status, "not_confirmed")   # not a clean negative either
                self.assertTrue(report.summary.startswith(
                    "inconclusive: redirected to http://shop.invalid/login?"), report.summary)
                self.assertIn("(final: http://shop.invalid/login?", report.evidence)
                self.assertNotIn("SECRET123", report.summary + report.evidence)
                self.assertEqual(len(target.requests), 2)   # /dashboard, then the redirect hop
        # Control: the same route answering without a redirect gets its normal verdict.
        report, _ = self._csp("csp", _page(), _serving(_HTML))
        self.assertEqual((report.status, report.confirmed), ("confirmed", True))

    def test_defect_injection_redirect_check_removed_is_detected(self):
        def app(method, url, headers):
            if url.endswith("/dashboard"):
                return 302, {"Location": "/login"}, ""
            return 200, _HTML, "<html>sign in</html>"

        with patch("harness.validators.csp_validator._same_route", lambda url, final_url: True):
            report, _ = self._csp("csp", _page(), _Target(app))
        # The login page's missing CSP stood in for the route.
        self.assertEqual((report.status, report.confirmed), ("confirmed", True))

    def test_secret_query_values_are_withheld_from_the_evidence(self):
        report, _ = self._csp("csp", _page("/dashboard?token=SECRET123&view=1"), _serving(_HTML))
        self.assertTrue(report.confirmed)
        self.assertNotIn("SECRET123", report.summary + report.evidence)
        self.assertIn("/dashboard?token=[REDACTED-SECRET]&view=1", report.evidence)   # the rest is kept

    def test_clickjacking_claim_is_decided_by_framing_protection_only(self):
        # XFO DENY and no CSP: the page cannot be framed, so no clickjacking
        # claim stands -- although CSP is missing.
        framed_off = {**_HTML, "X-Frame-Options": "DENY"}
        clickjacking, _ = self._csp("clickjacking", _page(), _serving(framed_off))
        self.assertEqual((clickjacking.status, clickjacking.confirmed), ("not_confirmed", False))
        csp, _ = self._csp("csp", _page(), _serving(framed_off))   # positive control: CSP IS missing
        self.assertEqual((csp.status, csp.confirmed), ("confirmed", True))

    def test_csp_claim_is_decided_by_csp_only(self):
        # An adequate CSP that does not restrict framing: framable, but CSP is fine.
        csp_only = {**_HTML, "Content-Security-Policy": _NO_FRAME_ANCESTORS_CSP}
        csp, _ = self._csp("csp", _page(), _serving(csp_only))
        self.assertEqual((csp.status, csp.confirmed), ("not_confirmed", False))
        clickjacking, _ = self._csp("clickjacking", _page(), _serving(csp_only))
        self.assertEqual((clickjacking.status, clickjacking.confirmed), ("confirmed", True))

    def test_defect_injection_one_verdict_for_both_checks_is_detected(self):
        # The old any() over both checks, restored: the clickjacking claim with
        # XFO DENY would be confirmed because CSP is missing.
        with patch("harness.validators.csp_validator._claim_kinds", return_value={"csp", "framing"}):
            report, _ = self._csp("clickjacking", _page(),
                                  _serving({**_HTML, "X-Frame-Options": "DENY"}))
        self.assertTrue(report.confirmed)

    def test_classes_headers_cannot_confirm_are_skipped_without_a_request(self):
        for claim in ("xss", "reflected xss", "security misconfiguration", "sql injection"):
            with self.subTest(claim=claim):
                target = _serving(_HTML)
                with target.patched():
                    result = asyncio.run(CspValidator(allowed_hosts=[HOST]).validate(
                        _finding(claim), _page()))
                self.assertEqual((result.status, result.confirmed), ("skipped", False))
                self.assertEqual(
                    result.summary, f"not supported: response headers cannot confirm {claim}")
                self.assertEqual(target.requests, [])

    def test_header_audit_sends_each_class_to_its_own_check(self):
        # What the universal audit passes as the class was one arbitrary member of
        # finding_classes (set order); it now names every class it audits, and
        # evaluates them all from ONE fetch of the exchange.
        self.assertEqual(set(CspValidator.audit_classes), {"csp", "clickjacking"})
        for audit_class in CspValidator.audit_classes:
            self.assertIn(audit_class, CspValidator.finding_classes)

        def audit(response_headers):
            """(sorted classes of the findings produced, requests sent) for one exchange."""
            orch = self._orch(hosts=(HOST,))
            orch.validator_registry.validators = {"csp": CspValidator(allowed_hosts=[HOST])}
            orch.validator_registry.active_enabled = True

            class _State:
                def __init__(self):
                    self.ingested = []

                def ingest_findings(self, url, method, findings):
                    self.ingested.append(findings)

                def _ep(self, *args):
                    pass

            state = _State()
            target = _serving(response_headers)

            async def go():
                async with RunContext.create(allowed_hosts=[HOST], max_requests=50,
                                             gate_config={"active_enabled": True}) as run:
                    return await universal_header_audit(orch, state, [_page()], run_context=run)

            with target.patched():
                asyncio.run(go())
            classes = sorted(f["vulnerability_class"] for findings in state.ingested for f in findings)
            return classes, target.requests

        for response_headers, expected in (
                (_HTML, ["clickjacking", "csp"]),
                ({**_HTML, "X-Frame-Options": "DENY"}, ["csp"]),
                ({**_HTML, "Content-Security-Policy": _NO_FRAME_ANCESTORS_CSP}, ["clickjacking"]),
                ({**_HTML, "Content-Security-Policy": _ADEQUATE_CSP}, [])):
            classes, requests = audit(response_headers)
            self.assertEqual(classes, expected)
            # Each class got its own verdict from the same single fetch.
            self.assertEqual([r[0] for r in requests], ["GET"], requests)

        original = CspValidator.audit
        # Defect injection: audit whichever class a set iteration yields first.
        async def one_arbitrary_class(self, exchange, classes=None):
            return await original(self, exchange, (next(iter(self.finding_classes)),))

        with patch.object(CspValidator, "audit", one_arbitrary_class):
            self.assertLess(len(audit(_HTML)[0]), 2)

        # Defect injection: one fresh fetch per class (the previous behaviour).
        async def fetch_per_class(self, exchange, classes=None):
            results = {}
            for audit_class in classes or self.audit_classes:
                results.update(await original(self, exchange, (audit_class,)))
            return results

        with patch.object(CspValidator, "audit", fetch_per_class):
            classes, requests = audit(_HTML)
        self.assertEqual(classes, ["clickjacking", "csp"])
        self.assertEqual(len(requests), 2)

    def test_audit_returns_one_verdict_per_class_from_one_fetch(self):
        global_throttle.configure(0)
        target = _serving({**_HTML, "X-Frame-Options": "DENY"})
        with target.patched():
            results = asyncio.run(CspValidator(allowed_hosts=[HOST]).audit(_page()))
        self.assertEqual({c: (r.finding_class, r.status, r.confirmed) for c, r in results.items()},
                         {"csp": ("csp", "confirmed", True),
                          "clickjacking": ("clickjacking", "not_confirmed", False)})
        self.assertEqual(len(target.requests), 1)
        # An unsupported class in the same call is skipped without costing a fetch.
        target = _serving(_HTML)
        with target.patched():
            results = asyncio.run(CspValidator(allowed_hosts=[HOST]).audit(_page(), ("xss",)))
        self.assertEqual((results["xss"].status, target.requests), ("skipped", []))


class CspIdentityTests(_Caller):
    """The fresh GET is the captured request's identity, not an anonymous one."""

    @staticmethod
    def _app(method, url, headers):
        if headers.get("authorization") == "Bearer alice-token" \
                and headers.get("cookie") == "sid=alice-session":
            return 200, {**_HTML, "Content-Security-Policy": _ADEQUATE_CSP}, "<html>dashboard</html>"
        return 401, {"Content-Type": "text/html"}, "<html>sign in</html>"

    @staticmethod
    def _captured(**extra):
        # The capture recorded no response CSP: only the fresh fetch can show it.
        return _page(request_headers={**_ALICE, "Host": HOST, "Content-Length": "0",
                                      "Connection": "keep-alive", "Accept": "text/html",
                                      "If-None-Match": '"abc"', "Accept-Encoding": "br", **extra})

    def test_fresh_fetch_carries_the_captured_identity(self):
        target = _Target(self._app)
        report, _ = self._csp("csp", self._captured(), target, sessions={"alice": _ALICE})
        self.assertEqual((report.status, report.confirmed), ("not_confirmed", False))
        self.assertIn("source: fresh", report.evidence)
        self.assertIn(f"Content-Security-Policy: {_ADEQUATE_CSP}", report.evidence)
        self.assertNotIn("No Content-Security-Policy header present", report.summary + report.evidence)
        (method, _url, sent), = target.requests
        self.assertEqual(method, "GET")
        self.assertEqual(sent["authorization"], "Bearer alice-token")
        self.assertEqual(sent["cookie"], "sid=alice-session")
        self.assertEqual(sent["accept"], "text/html")
        for dropped in ("host", "content-length", "connection", "if-none-match", "accept-encoding"):
            self.assertNotIn(dropped, sent)

    def test_defect_injection_anonymous_refetch_is_detected(self):
        with patch.object(CspValidator, "_replay_headers",
                          lambda self, exchange: {"User-Agent": self.user_agent}):
            report, _ = self._csp("csp", self._captured(), _Target(self._app),
                                  sessions={"alice": _ALICE})
        # The old behaviour: the anonymous 401 stood in for the route.
        self.assertEqual(report.status, "skipped")
        self.assertTrue(report.summary.startswith("not applicable: HTTP 401"), report.summary)

    def test_identity_is_not_replayed_without_a_session_for_it(self):
        exchange = self._captured()
        exchange.response_headers = {**_HTML, "Content-Security-Policy": _ADEQUATE_CSP}
        target = _Target(self._app)
        report, _ = self._csp("csp", exchange, target)   # no session registered for the credentials
        self.assertEqual([r for r in target.requests if "authorization" in r[2] or "cookie" in r[2]], [])
        # Falls back to what the captured response showed.
        self.assertIn("source: captured", report.evidence)
        self.assertIn(f"Content-Security-Policy: {_ADEQUATE_CSP}", report.evidence)
        self.assertEqual((report.status, report.confirmed), ("not_confirmed", False))

    def test_failed_fresh_fetch_falls_back_to_the_captured_headers(self):
        def down(method, url, headers):
            raise httpx.ConnectError("connection refused")

        captured_without_csp = _page()
        report, target = self._csp("csp", captured_without_csp, _Target(down))
        self.assertEqual(len(target.requests), 1)
        self.assertIn("source: captured", report.evidence)
        self.assertEqual((report.status, report.confirmed), ("confirmed", True))

        no_status = _page()
        no_status.response_status = None
        report, _ = self._csp("csp", no_status, _Target(down))
        self.assertEqual((report.status, report.confirmed), ("skipped", False))
        self.assertTrue(report.summary.startswith("inconclusive: no HTTP status"), report.summary)

    # Standalone (no RunContext, so no session registry decides where a credential
    # may go): only User-Agent, Accept and Accept-Language are sent, and no
    # redirect is followed. The in-scope server redirects to a second one (another
    # port, standing in for an off-scope host) that would answer a CSP-less page:
    # following would both forward the credentials there and decide the verdict on
    # its headers.
    _CREDENTIALS = {"Authorization": "Bearer alice-token", "Cookie": "sid=alice-session",
                    "X-API-Key": "key-123", "X-Auth-Token": "tok-456",
                    "Proxy-Authorization": "Basic cHJveHk6cHc=", "X-CSRF-Token": "csrf-789",
                    "Ocp-Apim-Subscription-Key": "apim-1", "X-Functions-Key": "fn-2",
                    "X-Access-Key": "access-3", "X-JWT-Assertion": "eyJhbGciOiJub25lIn0.e30.",
                    "X-Password": "hunter2", "X-Sid": "sid-4"}
    _CAPTURED = {**_CREDENTIALS, "Accept": "text/html", "Accept-Language": "en-US",
                 "Referer": "http://shop.invalid/", "X-Request-Id": "req-5"}
    _ALLOWED = {"user-agent", "accept", "accept-language"}
    # Sent by the HTTP client itself, whatever the captured request said.
    _TRANSPORT_GENERATED = {"host", "connection", "accept-encoding", "content-length"}

    def _assert_only_allowlisted(self, sent):
        self.assertEqual(sorted(set(sent) - self._ALLOWED - self._TRANSPORT_GENERATED), [])
        self.assertEqual((sent["accept"], sent["accept-language"]), ("text/html", "en-US"))

    def _standalone_redirect(self, claim="csp", location=None):
        """A standalone check of a route whose in-scope server answers 302 to
        `location(home, foreign)`: (result, home's requests, foreign's requests,
        the foreign server's /landing URL). `foreign` stands in for an off-scope
        host and answers a CSP-less HTML page on every path."""
        location = location or (lambda home, foreign: foreign.url("/landing?token=SECRET123"))
        global_throttle.configure(0)
        with _Server(lambda path, headers: (200, _HTML, "<html>foreign</html>")) as foreign, \
                _Server(lambda path, headers: (302, {"Location": location(home, foreign)}, "")) as home:
            exchange = HttpExchange(
                url=home.url("/dashboard"), method="GET", request_headers=dict(self._CAPTURED),
                response_status=200, response_headers=dict(_HTML), response_body="<html></html>")
            result = asyncio.run(CspValidator(allowed_hosts=["127.0.0.1"]).validate(
                _finding(claim), exchange))
            return result, list(home.requests), list(foreign.requests), foreign.url("/landing")

    def test_standalone_fetch_sends_only_the_allowlisted_headers_and_follows_no_redirect(self):
        for claim in ("csp", "clickjacking"):
            with self.subTest(claim=claim):
                result, home, foreign, landing = self._standalone_redirect(claim)
                self.assertEqual(foreign, [], "the redirect target was contacted")
                (_path, sent), = home
                self.assertEqual([n.lower() for n in self._CREDENTIALS if n.lower() in sent], [])
                self._assert_only_allowlisted(sent)
                # No verdict from the foreign page's (CSP-less) headers.
                self.assertEqual((result.status, result.confirmed), ("skipped", False))
                self.assertTrue(result.summary.startswith(f"inconclusive: redirected to {landing}"),
                                result.summary)
                self.assertNotIn("SECRET123", result.summary + result.evidence)

    def test_defect_injection_standalone_credentials_and_redirect_are_detected(self):
        # The old behaviour restored (every captured header replayed, redirects
        # followed and not noticed): the off-scope server receives the X-API-Key
        # and decides the verdict.
        real_client = httpx.AsyncClient

        def following(*args, **kwargs):
            return real_client(*args, **{**kwargs, "follow_redirects": True})

        class _Everything:
            def __contains__(self, name):
                return True

        with patch("harness.validators.csp_validator._STANDALONE_HEADERS", _Everything()), \
                patch("harness.validators.csp_validator._same_route", lambda url, final_url: True), \
                patch.object(httpx, "AsyncClient", following):
            result, home, foreign, _landing = self._standalone_redirect("csp")
        (_path, sent), = home
        self.assertEqual((sent["x-api-key"], sent["x-functions-key"], sent["x-password"]),
                         ("key-123", "fn-2", "hunter2"))
        (_path, forwarded), = foreign
        self.assertEqual(forwarded["x-api-key"], "key-123")
        self.assertEqual((result.status, result.confirmed), ("confirmed", True))

    def test_standalone_fetch_without_a_redirect_is_judged_normally(self):
        global_throttle.configure(0)
        with _Server(lambda path, headers: (200, _HTML, "<html></html>")) as home:
            exchange = HttpExchange(url=home.url("/dashboard"), method="GET",
                                    request_headers=dict(self._CAPTURED),
                                    response_status=200, response_headers=dict(_HTML))
            result = asyncio.run(CspValidator(allowed_hosts=["127.0.0.1"]).validate(
                _finding("csp"), exchange))
        (_path, sent), = home.requests
        self.assertEqual([n.lower() for n in self._CREDENTIALS if n.lower() in sent], [])
        self._assert_only_allowlisted(sent)
        self.assertEqual((result.status, result.confirmed), ("confirmed", True))
        self.assertIn("source: fresh", result.evidence)

    # A redirect that ends on the SAME path and differs in exactly one other
    # component of the route is still a redirect: the other route's headers say
    # nothing about this one. The Location is only read, never fetched.
    def _assert_redirect_is_inconclusive(self, location):
        """Returns (result, origin of the foreign server)."""
        result, home, foreign, landing = self._standalone_redirect("csp", location)
        self.assertEqual(len(home), 1, "the redirect was followed")
        self.assertEqual(foreign, [], "the redirect target was contacted")
        self.assertEqual((result.status, result.confirmed), ("skipped", False))
        self.assertTrue(result.summary.startswith("inconclusive: redirected to "), result.summary)
        self.assertTrue(result.summary.endswith("/dashboard"), result.summary)
        return result, landing[:-len("/landing")]

    def test_redirect_to_another_port_on_the_same_path_is_inconclusive(self):
        # Same scheme, host and path; only the port differs.
        result, foreign_origin = self._assert_redirect_is_inconclusive(
            lambda home, foreign: foreign.url("/dashboard"))
        self.assertEqual(result.summary, f"inconclusive: redirected to {foreign_origin}/dashboard")

    def test_redirect_to_another_host_on_the_same_path_is_inconclusive(self):
        # Same scheme, port and path; only the host differs (never resolved or contacted).
        result, _ = self._assert_redirect_is_inconclusive(
            lambda home, foreign: f"http://localhost:{home.port}/dashboard")
        self.assertTrue(result.summary.startswith("inconclusive: redirected to http://localhost:"),
                        result.summary)

    def test_redirect_to_another_scheme_on_the_same_path_is_inconclusive(self):
        # Same host, port and path; only the scheme differs (no TLS server is needed).
        result, _ = self._assert_redirect_is_inconclusive(
            lambda home, foreign: f"https://127.0.0.1:{home.port}/dashboard")
        self.assertTrue(result.summary.startswith("inconclusive: redirected to https://127.0.0.1:"),
                        result.summary)

    def test_redirect_that_changes_only_the_query_is_not_a_route_change(self):
        # Control: the same scheme, host, port and path (query aside) is the same route.
        result, home, foreign, _landing = self._standalone_redirect(
            "csp", lambda home, foreign: home.url("/dashboard?x=1"))
        self.assertEqual((len(home), foreign), (1, []))
        self.assertFalse(result.summary.startswith("inconclusive: redirected"), result.summary)
        self.assertTrue(result.summary.startswith("not applicable: HTTP 302"), result.summary)

    def test_same_route_compares_scheme_host_port_and_path(self):
        from harness.validators.csp_validator import _same_route
        base = "http://shop.invalid/dashboard"
        for final_url, same in (
                (base, True), (base + "?x=1#top", True), ("HTTP://SHOP.INVALID/dashboard", True),
                ("http://shop.invalid:80/dashboard", True),          # default port
                ("https://shop.invalid/dashboard", False),           # scheme
                ("http://other.invalid/dashboard", False),           # host
                ("http://shop.invalid:8080/dashboard", False),       # port
                ("http://shop.invalid/login", False)):               # path
            self.assertEqual(_same_route(base, final_url), same, final_url)
        self.assertTrue(_same_route("https://shop.invalid", "https://shop.invalid:443/"))


# ---------------------------------------------------------------- C. recon_validator
class ReconVerdictTests(_Caller):
    def _recon(self, claim, exchange, target=None):
        async def go():
            async with ReconValidator(allowed_hosts=[HOST], max_depth=0) as validator:
                return await validator.validate(_finding(claim), exchange)

        with (target or _Target()).patched():
            return asyncio.run(go())

    def test_technology_claim_with_no_technology_is_not_confirmed(self):
        result = self._recon("technology fingerprint", _page(response_headers=_HTML))
        self.assertEqual((result.status, result.confirmed, result.confidence),
                         ("not_confirmed", False, 0.0))
        self.assertIn("0 technologies", result.summary)

    def test_technology_claim_with_a_technology_is_confirmed_and_names_it(self):
        exchange = _page(response_headers={**_HTML, "Server": "nginx/1.18.0"})
        result = self._recon("technology fingerprint", exchange)
        self.assertEqual((result.status, result.confirmed, result.confidence),
                         ("confirmed", True, 0.95))
        self.assertIn("technologies (1): nginx 1.18.0", result.evidence)

    def test_class_reconnaissance_cannot_speak_to_is_skipped(self):
        for claim in ("sql injection", "recon", "reconnaissance", "cross site scripting"):
            with self.subTest(claim=claim):
                result = self._recon(claim, _page(response_headers={**_HTML, "Server": "nginx/1.18.0"}))
                self.assertEqual((result.status, result.confirmed, result.confidence),
                                 ("skipped", False, 0.0))
                self.assertEqual(result.summary,
                                 f"not supported: reconnaissance cannot confirm {claim}")

    def test_skipped_class_sends_no_request(self):
        exchange = _page(response_headers={**_HTML, "Server": "nginx/1.18.0"})
        for claim in ("sql injection", "recon", "reconnaissance", "cross site scripting"):
            with self.subTest(claim=claim):
                target = _Target()
                result = self._recon(claim, exchange, target)
                self.assertEqual(result.status, "skipped")
                self.assertEqual(target.requests, [])
        # Control: a class reconnaissance can speak to does crawl.
        target = _Target()
        self.assertEqual(self._recon("attack surface mapping", exchange, target).status, "not_confirmed")
        self.assertGreater(len(target.requests), 0)

    def test_secret_query_values_are_withheld_from_the_evidence(self):
        exchange = _page("/api/me?token=SECRET123&view=1", request_headers=_ALICE)
        result = self._recon("attack surface mapping", exchange)
        self.assertEqual((result.status, result.confirmed), ("confirmed", True))
        self.assertIn("sensitive endpoints (1): ", result.evidence)
        self.assertIn("/api/me?token=[REDACTED-SECRET]&view=1", result.evidence)
        self.assertNotIn("SECRET123", result.summary + result.evidence)

    def test_parameter_claim_needs_a_parameter(self):
        found = self._recon("hidden parameter", _page("/items?id=1"))
        self.assertEqual((found.status, found.confirmed), ("confirmed", True))
        self.assertIn("parameters (1): id", found.evidence)
        none = self._recon("hidden parameter", _page("/items"))
        self.assertEqual((none.status, none.confirmed), ("not_confirmed", False))
        self.assertIn("0 parameters", none.summary)

    def test_attack_surface_claim_needs_a_sensitive_endpoint(self):
        sensitive = self._recon("attack surface mapping", _page("/api/me", request_headers=_ALICE))
        self.assertEqual((sensitive.status, sensitive.confirmed), ("confirmed", True))
        self.assertIn(f"sensitive endpoints (1): {BASE}/api/me", sensitive.evidence)
        plain = self._recon("attack surface mapping", _page("/about"))
        self.assertEqual((plain.status, plain.confirmed), ("not_confirmed", False))
        self.assertIn("0 sensitive endpoints", plain.summary)

    def test_a_claim_of_several_kinds_needs_all_of_them(self):
        # "exposed server version": a technology AND an exposure.
        exchange = _page("/about", response_headers={**_HTML, "Server": "nginx/1.18.0"})
        result = self._recon("exposed server version", exchange)
        self.assertEqual((result.status, result.confirmed), ("not_confirmed", False))
        self.assertIn("0 sensitive endpoints", result.summary)
        self.assertNotIn("0 technologies", result.summary)

    def test_evidence_lists_at_most_ten_items_of_a_kind(self):
        query = "&".join(f"p{n:02d}=1" for n in range(12))
        result = self._recon("hidden parameter", _page("/items?" + query))
        self.assertEqual(result.status, "confirmed")
        self.assertIn("parameters (12): p00, p01, p02, p03, p04, p05, p06, p07, p08, p09 (+2 more)",
                      result.evidence)
        self.assertNotIn("p10", result.evidence)


if __name__ == "__main__":
    unittest.main()
