"""HU-2: GET /engagement/{host}/leads and the report's reproduction text.

Caller level: an owned loopback app, the production producers (record_observation,
persist_findings, the real TargetTransport ledger emission, Orchestrator.
_validate_findings, the sqlmap validator with its launch replaced by recorded
output), then the FastAPI endpoint and the Markdown report over the stored state.
The negative controls: a finding with no recorded exchange gets no request, and a
lead with no recorded blocker gets blocked_on null.
"""
import asyncio
import json
import time
import unittest

from fastapi.testclient import TestClient

from harness import leads, store
from harness.models import AgentReport, Finding, HttpExchange
from harness.report_generator import generate_markdown_report
from harness.run_context import RunContext, TypedRequest
from harness.test_proof_artifacts import _ProofCallerBase, _Target
from harness.test_sqlmap_points import _JSON_Q_BOOLEAN, _search_app, _sqlmap_says
from harness.validators.sqlmap import SqlmapValidator

COOKIE_SECRET = "c00kieS3cretValue991"
BEARER_SECRET = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.c2lnbmF0dXJlc2VjcmV0"
QUERY_SECRET = "qT0kenSecret778"
KEY_SECRET = "apiKeySecret4455"
SECRETS = (COOKIE_SECRET, BEARER_SECRET, QUERY_SECRET, KEY_SECRET, "c2lnbmF0dXJlc2VjcmV0")


def _app(method, path, headers, body):
    return 200, '{"ok": true}'


def _finding(cls, finding_id, **extra):
    return Finding(vulnerability_class=cls, confidence=extra.pop("confidence", 0.5),
                   severity=extra.pop("severity", "medium"), summary="candidate",
                   evidence="fixture", suggested_test=extra.pop("suggested_test", ""),
                   basis="derived", finding_id=finding_id, **extra)


class LeadsCallerTests(_ProofCallerBase, unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.target = _Target(_app)
        self.addCleanup(self.target.close)
        self.origin = self.target.origin
        self.host = self.origin.split("//", 1)[1]

    # ------------------------------------------------------------ producers
    def _send(self, finding_id, url, *, session_ref=None, max_requests=50):
        async def go():
            async with RunContext.create(allowed_hosts=list(self.HOSTS), max_requests=max_requests,
                                         gate_config={"active_enabled": True}) as run:
                return await run.target_transport().execute(
                    TypedRequest(method="GET", url=url), capability="leads_test",
                    session_ref=session_ref, case_ref=finding_id)
        return asyncio.run(go())

    def _seed(self):
        # 1. Captured exchange retained (record_observation) with secrets; no blocker.
        idor_ex = HttpExchange(
            url=f"{self.origin}/api/items/7?token={QUERY_SECRET}", method="GET",
            request_headers={"Cookie": f"sid={COOKIE_SECRET}",
                             "Authorization": f"Bearer {BEARER_SECRET}", "Accept": "application/json"},
            response_status=200, response_body='{"id": 7}')
        store.record_observation(idor_ex)
        store.persist_findings(idor_ex, "idor_agent", [_finding(
            "idor", "f-idor", severity="high", parameter_location="path", parameter_name="id")])

        # 2. No capture kept; the harness sent it (ledger EXECUTION blob), then a
        #    send was refused for an unknown session -> identity_missing.
        sqli_url = f"{self.origin}/search?q=x&api_key={KEY_SECRET}"
        sqli_ex = HttpExchange(url=sqli_url, method="GET", response_status=200)
        store.persist_findings(sqli_ex, "sqli_agent", [_finding(
            "sqli", "f-sqli", parameter_location="query", parameter_name="q",
            suggested_test="send q=x' and observe a database error")])
        self.assertEqual(self._send("f-sqli", sqli_url).outcome, "ok")
        self.assertEqual(self._send("f-sqli", sqli_url, session_ref="ghost").outcome, "unknown_session")

        # 3. A send refused by the request budget -> budget.
        budget_url = f"{self.origin}/orders"
        store.persist_findings(HttpExchange(url=budget_url, method="GET"), "authz_agent",
                               [_finding("bola", "f-budget")])
        self.assertEqual(self._send("f-budget", budget_url, max_requests=0).outcome, "budget_exhausted")

        # 4. No leg for the class, through the real confirmation path; nothing
        #    recorded -> no request (negative control) and no_leg.
        noleg_ex = HttpExchange(url=f"{self.origin}/about", method="GET", response_status=200)
        noleg = _finding("some_untested_class", "f-noleg")
        orch = self._orch(hosts=self.HOSTS)
        orch.validator_registry.validators = {}
        asyncio.run(orch._validate_findings(
            noleg_ex, [AgentReport(agent="generic", model="fake", findings=[noleg])]))
        store.persist_findings(noleg_ex, "generic", [noleg])

        # 5. Skipped by the worklist for time (from the investigation result) -> deadline.
        store.persist_findings(HttpExchange(url=f"{self.origin}/comments", method="GET"),
                               "xss_agent", [_finding("xss", "f-deadline", parameter_name="text")])

        # 6. A refuted candidate is not a lead.
        refuted = _finding("csrf", "f-refuted", review_verdict="unconfirmed_hypothesis")
        store.persist_findings(HttpExchange(url=f"{self.origin}/profile", method="POST"),
                               "csrf_agent", [refuted])

    def _seed_tool_reported(self):
        app = _Target(_search_app(blind=()))   # the fixture ignores q: sqlmap is not reproduced
        self.addCleanup(app.close)
        exchange = HttpExchange(
            url=app.origin + "/search", method="POST",
            request_headers={"Content-Type": "application/json"}, request_body='{"q": "x", "r": "y"}',
            response_status=200, response_body='{"rows": []}')
        cm = _sqlmap_says(_JSON_Q_BOOLEAN)
        cm.start()
        self.addCleanup(cm.stop)
        finding = _finding("sqli", "", suggested_test="verify")
        self._confirm("sqlmap", SqlmapValidator(allowed_hosts=list(self.HOSTS)), finding, exchange)
        store.persist_findings(exchange, "sqlmap", [finding])
        return app.origin.split("//", 1)[1]

    def _seed_investigation(self, host):
        import harness.server as server
        result = {
            "experiment_preflight": {"tasks": [
                {"task_id": "exp-op", "hypothesis_id": "h1", "status": "missing_prerequisite",
                 "reason": "declare owners",
                 "blocked_on": {"category": "operator_input", "inputs": ["owners declaration"]}},
                {"task_id": "exp-late", "hypothesis_id": "h2", "status": "deferred",
                 "reason": "stage deadline reached",
                 "blocked_on": {"category": "budget", "inputs": ["stage deadline reached"]}},
                {"task_id": "exp-done", "hypothesis_id": "h3", "status": "completed",
                 "reason": "stored attempt completed", "blocked_on": None}]},
            "prerequisite_blocks": [{"endpoint": "GET /admin/users", "identity": "p-admin",
                                     "missing": "no request captured as this identity",
                                     "action": "capture this request while signed in as admin",
                                     "checks_affected": 2}],
            "worklist_summary": {"skipped": [{"path": "/comments", "method": "GET",
                                              "reason": "time_budget"}]},
        }
        server._job_store().create({"job_id": "job-leads-1", "host": host, "base_url": self.origin,
                                    "status": "done", "started_at": time.time(),
                                    "finished_at": time.time(), "result": result})

    def _get(self, host):
        import harness.server as server
        client = TestClient(server.app, base_url="http://localhost",
                            headers={"Authorization": f"Bearer {server._mutation_token()}"})
        response = client.get(f"/engagement/{host}/leads")
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    # ---------------------------------------------------------------- tests
    def test_leads_endpoint_over_the_pipeline(self):
        self._seed()
        self._seed_investigation(self.host)
        body = self._get(self.host)
        self.assertEqual(body["schema_version"], leads.SCHEMA_VERSION)
        self.assertFalse(body["sends_traffic"])
        self.assertTrue(body["investigation"]["used"], body["investigation"])
        by_id = {l["finding_id"]: l for l in body["leads"] if l["kind"] == "finding"}
        self.assertEqual(set(by_id), {"f-idor", "f-sqli", "f-budget", "f-noleg", "f-deadline"})

        # Every lead carries a request or an explicit no-request reason, never both.
        for lead in body["leads"]:
            self.assertEqual(lead["request"] is None, bool(lead["no_request_reason"]), lead)
            self.assertTrue(lead["change"], lead)
            self.assertTrue(lead["expected"]["positive"] and lead["expected"]["negative"], lead)
            self.assertIn(lead["blocked_on"], (None, *leads.BLOCKED_CATEGORIES), lead)
        # Secrets never leave the endpoint.
        dumped = json.dumps(body)
        for secret in SECRETS:
            self.assertNotIn(secret, dumped)

        idor = by_id["f-idor"]
        self.assertEqual(idor["request"]["source"], "captured_observation")
        self.assertEqual(idor["request"]["method"], "GET")
        self.assertIn("/api/items/7", idor["request"]["url"])
        headers = {k.lower(): v for k, v in idor["request"]["headers"].items()}
        self.assertIn("cookie", headers)
        self.assertIn("authorization", headers)
        self.assertIn("REDACTED", headers["cookie"])
        self.assertIn("GET /api/items/7", idor["request"]["raw"])
        self.assertIn("different declared identity", idor["change"])
        self.assertIsNone(idor["blocked_on"], idor["blocked_facts"])   # negative control

        sqli = by_id["f-sqli"]
        self.assertEqual(sqli["request"]["source"], "ledger_execution")
        self.assertIn("/search", sqli["request"]["url"])
        self.assertIn("`q`", sqli["change"])
        self.assertEqual(sqli["blocked_on"], "identity_missing")
        self.assertIn("unknown_session", json.dumps(sqli["blocked_facts"]))

        self.assertEqual(by_id["f-budget"]["blocked_on"], "budget")
        self.assertIn("budget_exhausted", json.dumps(by_id["f-budget"]["blocked_facts"]))

        noleg = by_id["f-noleg"]
        self.assertIsNone(noleg["request"])      # negative control: nothing invented
        self.assertEqual(noleg["no_request_reason"], leads.NO_REQUEST_FINDING)
        self.assertEqual(noleg["blocked_on"], "no_leg")

        self.assertEqual(by_id["f-deadline"]["blocked_on"], "deadline")

        others = {l["lead_id"]: l for l in body["leads"] if l["kind"] != "finding"}
        kinds = sorted((l["kind"], l["blocked_on"]) for l in others.values())
        self.assertEqual(kinds, [("experiment", "deadline"), ("experiment", "operator_input"),
                                 ("prerequisite", "identity_missing")])
        for lead in others.values():
            self.assertIsNone(lead["request"])

        # Deterministic rank: 1..n, requests first, and stable across calls.
        self.assertEqual([l["rank"] for l in body["leads"]], list(range(1, len(body["leads"]) + 1)))
        with_request = [l["rank"] for l in body["leads"] if l["request"]]
        without = [l["rank"] for l in body["leads"] if not l["request"]]
        self.assertLess(max(with_request), min(without))
        self.assertEqual([l["lead_id"] for l in self._get(self.host)["leads"]],
                         [l["lead_id"] for l in body["leads"]])

    def test_without_investigation_result_blocked_on_uses_store_only(self):
        self._seed()
        body = self._get(self.host)
        self.assertFalse(body["investigation"]["used"])
        by_id = {l["finding_id"]: l for l in body["leads"]}
        self.assertIsNone(by_id["f-deadline"]["blocked_on"])   # no recorded deadline fact
        self.assertEqual({l["kind"] for l in body["leads"]}, {"finding"})

    def test_tool_reported_detection_is_a_lead(self):
        host = self._seed_tool_reported()
        body = self._get(host)
        self.assertEqual(len(body["leads"]), 1, body)
        lead = body["leads"][0]
        self.assertEqual(lead["blocked_on"], "tool_reported")
        self.assertEqual(lead["evidence_maturity"], "tool_reported")

    def test_report_uses_recipe_or_says_no_reproducible_request(self):
        self._seed()
        rows = store.all_host_findings(self.origin + "/")
        report = generate_markdown_report(self.host, rows)
        self.assertNotIn("replay the exact captured request", report)
        self.assertNotIn("secure baseline", report)

        def block(finding_class):
            start = report.index(f"### {finding_class} --")
            nxt = report.find("\n### ", start + 1)
            return report[start: nxt if nxt != -1 else len(report)]

        sqli = block("sqli")   # the harness sent it: the ledger recipe is used
        self.assertIn("**Recorded request(s) (reproduction recipe):**", sqli)
        self.assertIn("/search", sqli)
        self.assertNotIn(KEY_SECRET, sqli)
        self.assertIn("**Steps to reproduce:** send q=x'", sqli)
        noleg = block("some_untested_class")   # nothing sent, no suggested test
        self.assertIn(f"**Steps to reproduce:** {leads.NO_REPRO_TEXT}.", noleg)
        self.assertNotIn("reproduction recipe", noleg)


if __name__ == "__main__":
    unittest.main()
