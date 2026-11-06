"""The server-error ledger: 5xx answers to the run's own sends are scanned and
turned into findings and injection leads (harness.server_errors)."""
import unittest

from harness.server_errors import ServerErrorLedger, suspect_parameters

ORIGIN = "http://127.0.0.1:3000"
_STACK = ("Error: SQLITE_ERROR: near \"'\": syntax error\n"
          "    at Database.<anonymous> (/app/node_modules/sequelize/lib/dialects/sqlite/query.js:185:27)\n"
          "SELECT * FROM Users WHERE email = ''' AND password = '0192023a7bbd73250516f069df18b500'")


def _observe(ledger, url, status, body="", method="GET", request_body=None, ctype="",
             capability="sqli_probe"):
    ledger.observe(method=method, url=url, status=status, capability=capability,
                   body_fn=lambda: body, request_body=request_body, content_type=ctype)


class LedgerTests(unittest.TestCase):
    def test_a_stack_trace_in_a_5xx_is_a_confirmed_disclosure(self):
        led = ServerErrorLedger()
        _observe(led, f"{ORIGIN}/rest/products/search?q=apple", 200, body="[]")
        _observe(led, f"{ORIGIN}/rest/products/search?q=%27", 500, body=_STACK)
        disclosure = [f for f in led.findings() if f["vulnerability_class"] == "verbose_error_disclosure"]
        self.assertEqual(len(disclosure), 1)
        f = disclosure[0]
        self.assertTrue(f["confirmed"])
        self.assertEqual(f["confirmation_method"], "verbose_error_validator")
        self.assertEqual(f["url"], f"{ORIGIN}/rest/products/search")
        self.assertIn("1 of 2", f["summary"])

    def test_a_database_error_is_an_injection_lead_on_the_parameter_that_drew_it(self):
        led = ServerErrorLedger()
        _observe(led, f"{ORIGIN}/rest/products/search?q=%27))--&lang=en", 500, body=_STACK)
        lead = next(f for f in led.findings() if f["vulnerability_class"] == "sql_injection")
        self.assertFalse(lead["confirmed"])
        self.assertEqual((lead["parameter_location"], lead["parameter_name"]), ("query", "q"))
        self.assertEqual(lead["source"], "server_error")
        # the echoed query's literals and the password hash are masked
        self.assertNotIn("0192023a", lead["evidence"])
        self.assertIn("SQLITE_ERROR", lead["evidence"])

    def test_a_json_operator_body_is_suspect_input(self):
        self.assertEqual(suspect_parameters(f"{ORIGIN}/rest/user/login",
                                            '{"email": {"$ne": null}, "password": "x"}',
                                            "application/json"), [("body", "email")])
        self.assertEqual(suspect_parameters(f"{ORIGIN}/login", "email=a%27&password=x"),
                         [("body", "email")])

    def test_control_two_suspect_parameters_leave_the_lead_unbound(self):
        led = ServerErrorLedger()
        _observe(led, f"{ORIGIN}/rest/user/login", 500, body=_STACK, method="POST",
                 request_body='{"email": "a\'", "password": "b\'"}', ctype="application/json")
        lead = next(f for f in led.findings() if f["vulnerability_class"] == "sql_injection")
        self.assertNotIn("parameter_name", lead)

    def test_control_a_bare_5xx_is_reported_but_yields_no_finding(self):
        led = ServerErrorLedger()
        for _ in range(3):
            _observe(led, f"{ORIGIN}/rest/admin", 500, body="Internal Server Error",
                     capability="crawl")
        self.assertEqual(led.findings(), [])
        rep = led.report()
        self.assertEqual(rep["routes_with_5xx"], 1)
        row = rep["routes"][0]
        self.assertEqual((row["route"], row["errors_5xx"], row["all_5xx"]),
                         ("GET /rest/admin", 3, True))
        self.assertEqual(row["capabilities"], {"crawl": 3})

    def test_bodies_are_read_only_for_the_first_scans_of_a_5xx_route(self):
        led = ServerErrorLedger(max_scans=2)
        reads = []

        def body():
            reads.append(1)
            return "oops"
        for status in (200, 500, 500, 500, 404):
            led.observe(method="GET", url=f"{ORIGIN}/api/x/7", status=status, body_fn=body)
        self.assertEqual(len(reads), 2)
        self.assertEqual(led.report()["routes"][0]["errors_5xx"], 3)

    def test_control_observe_never_raises_into_the_send_path(self):
        led = ServerErrorLedger()

        def boom():
            raise RuntimeError("body gone")
        led.observe(method="GET", url=f"{ORIGIN}/a", status=500, body_fn=boom)
        led.observe(method="GET", url=None, status="500")
        self.assertEqual(led.report()["errors_5xx"], 1)

    def test_routes_past_the_cap_are_counted_not_tracked(self):
        led = ServerErrorLedger(max_routes=1)
        _observe(led, f"{ORIGIN}/a", 500)
        _observe(led, f"{ORIGIN}/b", 500)
        rep = led.report()
        self.assertEqual((rep["routes_with_5xx"], rep["errors_5xx"], rep["untracked_5xx"]), (1, 2, 1))


class ConfigTests(unittest.TestCase):
    def test_shipped_config_dispatches_no_lead_and_passive_forces_none(self):
        from pathlib import Path

        import yaml

        from harness import config_schema
        cfg = yaml.safe_load((Path(__file__).parent / "config.yaml").read_text(encoding="utf-8"))
        se = cfg["engagement"]["server_errors"]
        self.assertTrue(se["enabled"])                     # the passive ledger is on
        self.assertEqual(se["max_lead_confirmations"], 0)  # dispatch is off
        se["max_lead_confirmations"] = 3
        effective = config_schema.resolve_operating_profile(cfg, "passive-only")
        self.assertFalse(effective["engagement"]["server_errors"]["max_lead_confirmations"])
        # Negative control: another profile keeps an operator's raised budget.
        kept = config_schema.resolve_operating_profile(cfg, "workstation")
        self.assertEqual(kept["engagement"]["server_errors"]["max_lead_confirmations"], 3)


class _SearchServer:
    """Loopback search route: a quote in the query draws a 500 with a database error."""

    def __init__(self, error_body=_STACK):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        outer = self
        self.paths: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                outer.paths.append(self.path)
                broken = "%27" in self.path or "'" in self.path
                status, data = (500, error_body.encode()) if broken else (200, b"[]")
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.origin = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()


class ChainFollowUpTests(unittest.TestCase):
    """investigate_engagement follows up the server errors its own sends drew: the
    disclosure is recorded, and the database-error lead reaches the sqlmap leg with
    the route's captured template and the parameter that drew the error."""

    def setUp(self):
        self.nosql_seen = []

    def _run(self, max_leads, with_template=True, error_body=_STACK):
        import asyncio
        from unittest.mock import AsyncMock, patch
        from harness import engagement_builder, role_crawl, worklist_investigator
        from harness.engagement import EngagementState
        from harness.models import HttpExchange
        from harness.orchestrator import Orchestrator
        from harness.role_crawl import RoleSession
        from harness.run_context import RunContext
        from harness.test_chain_coverage_rvm import _chain_config
        from harness.validators.base import ValidationResult
        from harness.validators.sqlmap import SqlmapValidator
        from harness.validators.nosql_validator import NosqlValidator

        server = _SearchServer(error_body)
        self.addCleanup(server.close)
        base = server.origin + "/"

        async def build(base_url, roles, **kwargs):
            state = EngagementState(host="127.0.0.1")
            state.ingest_role_crawl({"endpoints": [{
                "method": "GET", "path": "/rest/products/search", "by_role": {"anonymous": 200},
                "reachable_roles": ["anonymous"], "object_scoped": False}]})
            if with_template:
                state.record_template(base + "rest/products/search?q=apple", "GET", HttpExchange(
                    url=base + "rest/products/search?q=apple", method="GET",
                    response_status=200, response_body="[]"))
            return state, role_crawl.RoleCrawlResult(base_url=base_url)

        async def investigate(*args, **kwargs):   # the sweep's own probe draws the 500
            await ctx.target_transport().send(
                "GET", base + "rest/products/search?q=%27))--", capability="sqli_probe")
            return []

        seen = []

        async def validate(self_, finding, exchange):
            seen.append((finding.parameter_location, finding.parameter_name, exchange.url))
            return ValidationResult("sqlmap", "confirmed", "sqli", confirmed=True,
                                    confidence=0.95, summary="boolean-blind on q")

        async def nosql_validate(self_, finding, exchange):
            self.nosql_seen.append(finding.vulnerability_class)
            return ValidationResult("nosql", "not_confirmed", "nosql")

        cfg = _chain_config()
        cfg["engagement"]["server_errors"] = {"enabled": True, "max_lead_confirmations": max_leads}
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["127.0.0.1"]
        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], config=cfg)

        async def go():
            try:
                return await orch.investigate_engagement(
                    base, [RoleSession("anonymous", {})], max_nodes=1, max_chain_rounds=0,
                    discovery_max_probes=1, run_context=ctx)
            finally:
                await ctx.aclose()
        with patch.object(engagement_builder, "build_engagement", new=build), \
                patch.object(worklist_investigator, "investigate_worklist", new=investigate), \
                patch("harness.orchestrator_chain.review_captured_exchanges",
                      new=AsyncMock(return_value=0)), \
                patch("harness.orchestrator_chain.universal_header_audit",
                      new=AsyncMock(return_value=0)), \
                patch.object(SqlmapValidator, "validate", new=validate), \
                patch.object(NosqlValidator, "validate", new=nosql_validate), \
                patch.object(orch, "_persist_confirmation_proof",
                             new=AsyncMock(return_value=(True, {"proof_id": "p-1"}, ""))):
            result = asyncio.run(go())
        by_class = {f["vulnerability_class"]: f for f in result["findings"]
                    if f.get("url", "").endswith("/rest/products/search")}
        return result, by_class, seen

    def test_the_lead_reaches_the_sqlmap_leg_on_the_parameter_that_drew_the_error(self):
        result, by_class, seen = self._run(max_leads=2)
        self.assertEqual(len(seen), 1)
        loc, name, url = seen[0]
        self.assertEqual((loc, name), ("query", "q"))
        self.assertIn("q=apple", url)          # the captured template, not the payload
        self.assertTrue(by_class["sql_injection"]["confirmed"])
        self.assertTrue(by_class["verbose_error_disclosure"]["confirmed"])
        rep = result["server_errors"]
        self.assertEqual((rep["leads"], rep["leads_dispatched"], rep["leads_confirmed"]), (1, 1, 1))
        self.assertEqual(rep["ledger"]["routes"][0]["route"], "GET /rest/products/search")

    def test_without_a_template_the_named_query_parameter_gets_a_neutral_value(self):
        _, by_class, seen = self._run(max_leads=1, with_template=False)
        self.assertEqual(len(seen), 1)
        self.assertTrue(seen[0][2].endswith("/rest/products/search?q=1"), seen[0][2])

    def test_a_nosql_lead_reaches_the_nosql_leg_never_sqlmap(self):
        # "nosql injection" contains "sql injection": the dispatch used to send every
        # NoSQL finding to sqlmap.
        _, by_class, seen = self._run(
            max_leads=1, error_body="MongoServerError: unknown operator: $foo")
        self.assertEqual(seen, [])
        self.assertEqual(self.nosql_seen, ["nosql_injection"])
        self.assertFalse(by_class["nosql_injection"]["confirmed"])

    def test_control_with_no_lead_budget_the_lead_stays_a_lead(self):
        result, by_class, seen = self._run(max_leads=0)
        self.assertEqual(seen, [])
        self.assertFalse(by_class["sql_injection"]["confirmed"])
        self.assertTrue(by_class["verbose_error_disclosure"]["confirmed"])
        self.assertEqual(result["server_errors"]["leads_not_dispatched"],
                         {"max_lead_confirmations": 1})


if __name__ == "__main__":
    unittest.main()
