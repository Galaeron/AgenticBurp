"""Exposure leads -> verdicts (r9): directory listings, extension-filter bypass,
metrics and .well-known.

r9 raised `exposed_directory_listing`, `exposed_metrics_endpoint` and
`public_metrics_endpoint` leads. No validator matched them, so each got "no
confirmation validator available". The passive AV-EXPOSURE-01 leg confirmed the
same captures with no exchange behind its verdict, which is a legacy proof.

The fixture is a generic loopback app. It has an HTML directory index whose files
pass through an extension allow-list that a NUL encoding defeats, a JSON file
listing, a listing of harmless files, a metrics route, a credential-gated metrics
route, a plain-text status route, an HTML page with no listing, and security.txt
with CSAF provider metadata. A second mode makes the filter strict, so the bypass
fails.

Two production callers are driven. Orchestrator._validate_findings handles agent
leads. Orchestrator.investigate_engagement runs the coverage drive and owns the
AV-EXPOSURE-02/03, AV-FILTER-01 and AV-WELLKNOWN-01 cells. Each confirmation must
name three distinct exchanges that strict accounting resolves. Each behaviour also
has a negative control.
"""
import asyncio
import json
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import unquote

from harness import cache, global_throttle, safety_gate, store
from harness.coverage_model import CHECKS_BY_ID, CellStatus
from harness.models import AgentReport, Finding, HttpExchange
from harness.validators.exposure_leads import (
    FilterBypassValidator, ListingExposureValidator, MetricsExposureValidator, WellKnownValidator,
    classify_listed_file, is_metrics_exposition, parse_listing, parse_security_txt, summarize_metrics)

_FILES = {
    "notes.md": b"# Notes\nThe team meeting moved to Tuesday.\n",
    "plan.md": b"# Roadmap\nCONFIDENTIAL - internal use only.\nQ3 targets are below.\n",
    "app.conf.bak": b"[database]\nhost = db.internal\npassword = fixture-s3cret\n",
    "vault.kdbx": bytes([0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5]) + b"keystore-fixture",
}
_DOCS = {"readme.md": b"# Readme\nInstall with make.\n", "guide.md": b"# Guide\nStep one.\n"}
_EXPORTS = {"users.sql": b"CREATE TABLE users (id int, email text);\nINSERT INTO users VALUES (1, 'a@x.test');\n",
            "about.md": b"# Exports\nNightly.\n"}
_ALLOWED = (".md", ".pdf")
_METRICS = ("# HELP http_requests_total Requests served.\n# TYPE http_requests_total counter\n"
            'http_requests_total{method="get",route="/files"} 12\n'
            "# HELP app_build_info Build information.\n# TYPE app_build_info gauge\n"
            'app_build_info{version="4.2.1",runtime_version="v20.11.0"} 1\n'
            "# HELP process_resident_memory_bytes Resident memory.\n"
            "# TYPE process_resident_memory_bytes gauge\nprocess_resident_memory_bytes 5.1e+07\n")


def _index(title, directory, names, *, relative=False):
    # relative: the links a slashless `/dir` page carries (`dir/name`), resolved as a
    # browser resolves them. That page also links `.` and `dir` itself.
    leaf = directory.strip("/")
    prefix = f"{leaf}/" if relative else f"{directory}/"
    rows = "".join(f'<li><a href="{prefix}{n}">{n}</a></li>' for n in names)
    crumbs = f'<a href=".">~</a> / <a href="{leaf}">{leaf}</a>' if relative else '<a href="/">..</a>'
    return (f"<!DOCTYPE html><html><head><title>{title}</title></head><body>"
            f'{crumbs} <a href="?C=N;O=D">Name</a><ul>{rows}</ul></body></html>').encode()


class _App(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body=b"", ctype="text/plain; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def serve_filtered(self, raw):
        once = unquote(raw)
        if self.server.strict:
            name = unquote(once)
            if "\x00" in name or not name.endswith(_ALLOWED):
                return self.reply(403, b"Only .md and .pdf files are allowed!")
        else:
            # The filter checks the once-decoded name; the file layer decodes again
            # and stops at a NUL (the classic poison-null-byte shape).
            if not once.endswith(_ALLOWED):
                return self.reply(403, b"Only .md and .pdf files are allowed!")
            name = unquote(once).split("\x00", 1)[0]
        if name not in _FILES:
            return self.reply(404, b"Not found")
        return self.reply(200, _FILES[name], "application/octet-stream")

    def do_GET(self):
        self.server.received.append(self.path)
        path = self.path.split("?", 1)[0]
        port = self.server.server_port
        if path == "/files":
            return self.reply(200, _index("listing directory /files", "/files", list(_FILES), relative=True),
                              "text/html")
        if path.startswith("/files/"):
            return self.serve_filtered(path[len("/files/"):])
        if path == "/docs":
            return self.reply(200, _index("Index of /docs", "/docs", list(_DOCS)), "text/html")
        if path.startswith("/docs/") and path[6:] in _DOCS:
            return self.reply(200, _DOCS[path[6:]], "text/markdown")
        if path == "/exports":
            doc = {"files": [{"name": n, "size": len(b), "type": "file"} for n, b in _EXPORTS.items()]}
            return self.reply(200, json.dumps(doc).encode(), "application/json")
        if path.startswith("/exports/") and path[9:] in _EXPORTS:
            return self.reply(200, _EXPORTS[path[9:]], "application/octet-stream")
        if path == "/metrics":
            return self.reply(200, _METRICS.encode(), "text/plain; version=0.0.4")
        if path == "/private-metrics":
            if not self.headers.get("Authorization"):
                return self.reply(401, b'{"error":"login required"}', "application/json")
            return self.reply(200, _METRICS.encode(), "text/plain; version=0.0.4")
        if path == "/status":
            return self.reply(200, b"status: ok\nuptime_seconds 12\nqueue_depth 3\n")
        if path == "/page":
            return self.reply(200, b"<html><head><title>Home</title></head><body>"
                                   b'<a href="/page/a.md">a</a></body></html>', "text/html")
        if path == "/.well-known/security.txt" and self.server.well_known:
            return self.reply(200, (f"Contact: mailto:security@fixture.test\n"
                                    f"Expires: 2030-01-01T00:00:00Z\nPreferred-Languages: en\n"
                                    f"CSAF: http://127.0.0.1:{port}/.well-known/csaf/provider-metadata.json\n"
                                    ).encode())
        if path == "/.well-known/csaf/provider-metadata.json" and self.server.well_known:
            doc = {"canonical_url": f"http://127.0.0.1:{port}/.well-known/csaf/provider-metadata.json",
                   "metadata_version": "2.0", "role": "csaf_trusted_provider",
                   "publisher": {"name": "Fixture Org", "category": "vendor", "namespace": "https://fixture.test"},
                   "distributions": [{"directory_url": f"http://127.0.0.1:{port}/advisories/"}]}
            return self.reply(200, json.dumps(doc).encode(), "application/json")
        return self.reply(404, b"Not found")


class _Fixture(unittest.TestCase):
    strict = False
    well_known = True

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="exposure_leads_")
        self._saved = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()
        st = global_throttle.throttle.stats()
        prev = (st["rate_per_second"] if st["enabled"] else 0.0, st["burst"] if st["enabled"] else None)
        self.addCleanup(lambda: global_throttle.configure(*prev))
        global_throttle.configure(0)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _App)
        self.server.received = []
        self.server.strict = self.strict
        self.server.well_known = self.well_known
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        store._DB_PATH, cache._cache = self._saved
        safety_gate.reset_default_gate()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def capture(self, path, headers=None):
        """The fixture's real answer to one GET, as a captured exchange."""
        import urllib.request
        req = urllib.request.Request(self.origin + path, headers=dict(headers or {}))
        try:
            with urllib.request.urlopen(req) as resp:
                status, rheaders, body = resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as err:
            status, rheaders, body = err.code, dict(err.headers), err.read()
        self.server.received.clear()
        return HttpExchange(url=self.origin + path, method="GET", request_headers=dict(headers or {}),
                            response_status=status, response_headers=rheaders,
                            response_body=body.decode("utf-8", errors="replace"))


# --------------------------------------------------------------------------- #
# Oracles
# --------------------------------------------------------------------------- #

class OracleTests(_Fixture):
    def test_html_and_json_listings_parse_and_other_pages_do_not(self):
        names = [e.name for e in parse_listing(self.capture("/files"))]
        self.assertEqual(names, list(_FILES))      # parent and sort links dropped
        self.assertEqual([(e.name, e.size) for e in parse_listing(self.capture("/exports"))],
                         [(n, len(b)) for n, b in _EXPORTS.items()])
        for path in ("/page", "/status", "/metrics"):
            self.assertEqual(parse_listing(self.capture(path)), [], path)
        # Bare names on a slashless page that assumes a trailing slash still list.
        bare = HttpExchange(url=self.origin + "/pub", method="GET", response_status=200,
                            response_headers={"Content-Type": "text/html"},
                            response_body='<title>Index of /pub</title><a href="../">..</a>'
                                          '<a href="a.txt">a.txt</a><a href="b.tar.gz">b.tar.gz</a>')
        self.assertEqual([e.url for e in parse_listing(bare)],
                         [self.origin + "/pub/a.txt", self.origin + "/pub/b.tar.gz"])
        words = HttpExchange(url=self.origin + "/api/colors", method="GET", response_status=200,
                             response_headers={"Content-Type": "application/json"},
                             response_body='["red", "green", "blue"]')
        self.assertEqual(parse_listing(words), [])

    def test_classification_is_generic(self):
        def kind(name, body):
            found = classify_listed_file(name, 200, {}, body)
            return found.label if found else None
        self.assertEqual(kind("app.conf.bak", "password = x1234567\n"), "backup_file")
        self.assertEqual(kind("site.pem", "-----BEGIN PRIVATE KEY-----\nMIIE\n"), "private_key")
        self.assertEqual(kind("vault.kdbx", "\x03\xd9binary"), "key_or_keystore")
        self.assertEqual(kind("settings.txt", "api_key: abcd1234efgh\n"), "credentials")
        self.assertEqual(kind("plan.md", "# Plan\nCONFIDENTIAL\n"), "confidential_document")
        self.assertEqual(kind("package.json", '{"name": "x", "dependencies": {"a": "1.0.0"}}'),
                         "package_manifest")
        self.assertEqual(kind("dump.sql", "CREATE TABLE t (a int);\nINSERT INTO t VALUES (1);"), "sql_dump")
        self.assertEqual(kind("app.db", "SQLite format 3\x00..."), "database_or_dump")
        # Harmless documents and a catch-all HTML page are not sensitive.
        self.assertIsNone(kind("notes.md", "# Notes\nMeeting on Tuesday.\n"))
        self.assertIsNone(kind("secret.bak", "<!DOCTYPE html><html><body>app</body></html>"))
        self.assertIsNone(classify_listed_file("app.conf.bak", 403, {}, "Only .md allowed"))

    def test_metrics_and_security_txt_oracles(self):
        self.assertTrue(is_metrics_exposition(200, {"Content-Type": "text/plain"}, _METRICS))
        self.assertFalse(is_metrics_exposition(200, {"Content-Type": "text/plain"},
                                               "status: ok\nuptime_seconds 12\n"))
        self.assertFalse(is_metrics_exposition(401, {}, _METRICS))
        summary = summarize_metrics(_METRICS)
        self.assertEqual(summary["family_count"], 3)
        self.assertIn("route", summary["label_keys"])
        self.assertEqual(summary["versions"]["app_build_info.version"], "4.2.1")
        parsed = parse_security_txt(200, {}, "Contact: mailto:s@x.test\nExpires: 2001-01-01T00:00:00Z\n")
        self.assertTrue(parsed["expired"])
        self.assertIsNone(parse_security_txt(200, {}, "<html><title>Not found</title></html>"))
        self.assertIsNone(parse_security_txt(200, {}, "Policy: https://x.test/p\n"))   # no Contact

    def test_coverage_cells_are_legs(self):
        from harness.coverage_tracker import _LEG_CONFIRMATIONS, _PASSIVE_LEG_CONFIRMATIONS
        for check_id, family in (("AV-EXPOSURE-02", "listing_exposure"), ("AV-FILTER-01", "filter_bypass"),
                                 ("AV-EXPOSURE-03", "metrics_exposure"), ("AV-WELLKNOWN-01", "well_known")):
            check = CHECKS_BY_ID[check_id]
            self.assertEqual(check.confirmation, family)
            self.assertIn(family, _LEG_CONFIRMATIONS)
            self.assertNotIn(family, _PASSIVE_LEG_CONFIRMATIONS)   # they send
        self.assertTrue(CHECKS_BY_ID["AV-WELLKNOWN-01"].origin_scoped)
        self.assertEqual(CHECKS_BY_ID["AV-FILTER-01"].canonical_class(), "path_traversal")


# --------------------------------------------------------------------------- #
# Agent leads through Orchestrator._validate_findings
# --------------------------------------------------------------------------- #

def _finding(cls):
    return Finding(vulnerability_class=cls, confidence=0.6, summary="lead", evidence="capture",
                   suggested_test="fetch", basis="derived")


class AgentLeadCallerTests(_Fixture):
    def dispatch(self, path, cls, *, agent="info_disclosure", headers=None):
        """One agent lead through Orchestrator._validate_findings with the production
        registry; returns ({validator: report}, proofs, sends to the fixture)."""
        from harness.orchestrator import Orchestrator
        from harness.run_context import RunContext
        from harness.test_default_history_caller import _RecordingModel, _config
        exchange = self.capture(path, headers)
        cfg = _config()
        cfg["server"]["allowed_hosts"] = ["127.0.0.1"]
        cfg["validators"].update(active_enabled=True)
        orch = Orchestrator(cfg)
        model = _RecordingModel()
        orch.ollama = model
        for a in orch.agent_manager.agents.values():
            a.ollama = model
        keep = ("listing_exposure", "filter_bypass", "metrics_exposure", "well_known", "content_exposure")
        orch.validator_registry.validators = {k: v for k, v in orch.validator_registry.validators.items()
                                              if k in keep}

        async def go():
            run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=200, config=cfg,
                                    gate_config={"active_enabled": True})
            run.sessions.register("a", "alice", {"Authorization": "Bearer a"}, allowed_origins=[self.origin])
            async with run:
                reports, proofs = await orch._validate_findings(
                    exchange, [AgentReport(agent=agent, model="fake", findings=[_finding(cls)])],
                    run_context=run)
            await run.aclose()
            return reports, proofs

        reports, proofs = asyncio.run(go())
        return {r.validator: r for r in reports}, proofs, list(self.server.received)

    def assert_proof_bound(self, proofs, validator):
        from harness.assessment_health import stored_proof_artifacts_resolve
        mine = [p for p in proofs if p.get("validator") == validator and p.get("attack_artifact_id")]
        self.assertTrue(mine, proofs)
        proof = mine[-1]
        self.assertFalse(proof.get("legacy", True), proof)
        ids = [proof["baseline_artifact_id"], proof["attack_artifact_id"], *proof.get("control_artifact_ids", [])]
        self.assertGreaterEqual(len(set(filter(None, ids))), 3, ids)
        self.assertTrue(stored_proof_artifacts_resolve(proof), proof)

    def test_r9_listing_shapes_reach_a_verdict(self):
        for cls in ("exposed_directory_listing", "information_disclosure", "endpoint_discovery"):
            with self.subTest(cls=cls):
                reports, proofs, sent = self.dispatch("/files", cls)
                report = reports["listing_exposure_validator"]
                self.assertEqual(report.status, "confirmed", report.summary)
                self.assertIn("plan.md: confidential_document", report.evidence)
                # The refused files are named; their values never are.
                self.assertIn("app.conf.bak (HTTP 403)", report.evidence)
                self.assertNotIn("fixture-s3cret", report.evidence + report.summary)
                self.assert_proof_bound(proofs, "listing_exposure_validator")
                self.assertTrue(all(p.startswith("/files") for p in sent), sent)

    def test_json_listing_confirms_a_dump(self):
        reports, proofs, _sent = self.dispatch("/exports", "sensitive_file_exposure")
        report = reports["listing_exposure_validator"]
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertIn("users.sql: sql_dump (high)", report.evidence)
        self.assert_proof_bound(proofs, "listing_exposure_validator")

    def test_harmless_listing_is_a_negative_with_artifacts(self):
        reports, _proofs, sent = self.dispatch("/docs", "exposed_directory_listing")
        report = reports["listing_exposure_validator"]
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertEqual(sorted(p for p in sent if p in ("/docs/readme.md", "/docs/guide.md")),
                         ["/docs/guide.md", "/docs/readme.md"])

    def test_no_listing_routes_no_listing_leg_and_sends_nothing(self):
        reports, _proofs, sent = self.dispatch("/page", "exposed_directory_listing")
        self.assertNotIn("listing_exposure_validator", reports)
        self.assertNotIn("filter_bypass_validator", reports)
        self.assertEqual(sent, [])

    def test_bypass_lead_confirms_with_both_controls(self):
        reports, proofs, sent = self.dispatch("/files", "path_filter_bypass", agent="path_traversal")
        report = reports["filter_bypass_validator"]
        self.assertEqual(report.status, "confirmed", report.summary)
        self.assertIn("app.conf.bak%2500.md", report.summary)
        self.assertIn("positive control: notes.md%2500.md returned the exact bytes", report.evidence)
        self.assertIn("negative control: av-absent-", report.evidence)
        self.assertNotIn("fixture-s3cret", report.evidence)
        self.assert_proof_bound(proofs, "filter_bypass_validator")
        self.assertTrue(any("%2500" in p for p in sent), sent)

    def test_r9_metrics_shapes_reach_a_verdict(self):
        for cls, agent in (("exposed_metrics_endpoint", "info_disclosure"),
                           ("public_metrics_endpoint", "info_disclosure"),
                           ("broken_authentication", "auth")):
            with self.subTest(cls=cls):
                reports, proofs, sent = self.dispatch("/metrics", cls, agent=agent)
                report = reports["metrics_exposure_validator"]
                self.assertEqual(report.status, "confirmed", report.summary)
                self.assertIn("3 metric families", report.evidence)
                self.assertIn("app_build_info.version=4.2.1", report.evidence)
                self.assert_proof_bound(proofs, "metrics_exposure_validator")

    def test_credential_gated_metrics_is_not_exposed(self):
        reports, _proofs, _sent = self.dispatch("/private-metrics", "exposed_metrics_endpoint",
                                                headers={"Authorization": "Bearer a"})
        report = reports["metrics_exposure_validator"]
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertIn("HTTP 401", report.summary)

    def test_non_metrics_text_route_routes_no_metrics_leg(self):
        reports, _proofs, sent = self.dispatch("/status", "exposed_metrics_endpoint")
        self.assertNotIn("metrics_exposure_validator", reports)
        self.assertEqual(sent, [])


class StrictFilterCallerTests(AgentLeadCallerTests):
    """A filter that decodes fully and refuses NULs: the bypass must not confirm."""
    strict = True

    def test_bypass_lead_confirms_with_both_controls(self):
        reports, _proofs, sent = self.dispatch("/files", "path_filter_bypass", agent="path_traversal")
        report = reports["filter_bypass_validator"]
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertIn("filter held", report.summary)
        self.assertTrue(any("%2500" in p for p in sent), sent)

    # The other agent-lead cases do not depend on the filter mode.
    test_r9_listing_shapes_reach_a_verdict = None
    test_json_listing_confirms_a_dump = None
    test_harmless_listing_is_a_negative_with_artifacts = None
    test_no_listing_routes_no_listing_leg_and_sends_nothing = None
    test_r9_metrics_shapes_reach_a_verdict = None
    test_credential_gated_metrics_is_not_exposed = None
    test_non_metrics_text_route_routes_no_metrics_leg = None


# --------------------------------------------------------------------------- #
# Coverage cells through Orchestrator.investigate_engagement
# --------------------------------------------------------------------------- #

_DRIVEN = ("/files", "/docs", "/exports", "/metrics", "/status", "/page")
_FAMILIES = ("listing_exposure", "filter_bypass", "metrics_exposure", "well_known")


class CoverageDriveCallerTests(_Fixture):
    def drive(self, enabled=True):
        from harness import test_smoke_investigate as smoke
        from harness.coverage_tracker import _LEG_CONFIRMATIONS
        from harness.engagement import EngagementState
        from harness.orchestrator import Orchestrator
        from harness.role_crawl import RoleCrawlResult, RoleSession
        from harness.run_context import RunContext
        from harness.test_coverage_capabilities import _controlled_model
        captures = {path: self.capture(path) for path in _DRIVEN}
        cfg = smoke._test_config()
        for name in _LEG_CONFIRMATIONS:
            cfg["validators"].setdefault(name, {})["enabled"] = False
        for name in _FAMILIES:
            cfg["validators"][name]["enabled"] = enabled
        orch = Orchestrator(cfg)
        _controlled_model(orch)
        orch.business_context_enabled = False
        orch.engagement_coverage_drive = True
        orch.engagement_coverage_case_drive = True
        orch.run_active_probe = AsyncMock(return_value={"iterative_result": {"findings": []}, "integration": {}})
        base = self.origin

        def build(*args, **kwargs):
            state = EngagementState("127.0.0.1")
            for path, ex in captures.items():
                state.record_template(base + path, "GET", ex)
            for ep in state.endpoints.values():
                ep.reachable_roles = ["anonymous"]
            return state, RoleCrawlResult(base_url=base)

        ctx = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=400, config=cfg,
                                gate_config={"active_enabled": True})

        async def run():
            async with ctx:
                return await orch.investigate_engagement(
                    base, [RoleSession("anonymous", {})], max_nodes=0, step_budget=1,
                    max_chain_rounds=0, active_discovery=False, run_context=ctx)

        with patch("harness.engagement_builder.build_engagement", side_effect=build):
            result = asyncio.run(run())
        cells = result["coverage"]["phase_ledger"]["cells"]
        return cells, result["findings"], list(self.server.received)

    @staticmethod
    def rows(cells, check_id, path=None):
        return [r for r in cells if r["check"] == check_id
                and (path is None or r["endpoint"].endswith(" " + path))]

    def test_drive_confirms_each_cell_and_keeps_its_negatives(self):
        cells, findings, sent = self.drive()
        status = lambda check, path=None: {r["observation_status"] for r in self.rows(cells, check, path)}
        self.assertEqual(status("AV-EXPOSURE-02", "/files"), {CellStatus.CONFIRMED.value})
        self.assertEqual(status("AV-EXPOSURE-02", "/exports"), {CellStatus.CONFIRMED.value})
        self.assertEqual(status("AV-EXPOSURE-02", "/docs"), {CellStatus.NOT_DETECTED.value})
        self.assertEqual(status("AV-EXPOSURE-03", "/metrics"), {CellStatus.CONFIRMED.value})
        # Shape gates: no listing, no exposition -> never attempted, never a negative.
        for check, path in (("AV-EXPOSURE-02", "/page"), ("AV-EXPOSURE-03", "/status"),
                            ("AV-FILTER-01", "/page"), ("AV-EXPOSURE-03", "/files")):
            rows = self.rows(cells, check, path)
            self.assertTrue(rows and all(not r["attempted"] for r in rows), (check, path, rows))
        self.assertEqual(status("AV-FILTER-01", "/files"), {CellStatus.CONFIRMED.value})
        # A listing that refuses nothing has no filter to bypass: a tested negative.
        self.assertEqual(status("AV-FILTER-01", "/docs"), {CellStatus.NOT_DETECTED.value})
        well_known = [r for r in self.rows(cells, "AV-WELLKNOWN-01")
                      if r["observation_status"] == CellStatus.CONFIRMED.value]
        self.assertEqual(len(well_known), 1, self.rows(cells, "AV-WELLKNOWN-01"))
        self.assertEqual(sent.count("/.well-known/security.txt"), 1, sent)

        by_leg = {}
        for f in findings:
            by_leg.setdefault(f.get("confirmed_by_leg"), []).append(f)
        bypass = by_leg.get("filter_bypass_validator", [])
        self.assertTrue(bypass and all(f["vulnerability_class"] == "path_filter_bypass" for f in bypass), bypass)
        self.assertTrue(all(f.get("proof_id") for f in bypass), bypass)
        listing = by_leg.get("listing_exposure_validator", [])
        self.assertTrue(listing and all(f["vulnerability_class"] == "info_disclosure" for f in listing))
        observation = by_leg.get("well_known_validator", [])
        self.assertTrue(observation and all(f["severity"] == "info" for f in observation), observation)
        self.assertTrue(by_leg.get("metrics_exposure_validator"))
        self.assertTrue(all(not p.startswith(("/status", "/page")) for p in sent), sent)

    def test_disabled_legs_are_unavailable_and_send_nothing(self):
        cells, findings, sent = self.drive(enabled=False)
        for check in ("AV-EXPOSURE-02", "AV-FILTER-01", "AV-EXPOSURE-03", "AV-WELLKNOWN-01"):
            rows = self.rows(cells, check)
            self.assertTrue(rows and all(not r["attempted"] for r in rows), (check, rows))
        legs = {"listing_exposure_validator", "filter_bypass_validator",
                "metrics_exposure_validator", "well_known_validator"}
        self.assertFalse([f for f in findings if f.get("confirmed_by_leg") in legs])
        self.assertFalse([p for p in sent if p.startswith(("/files/", "/.well-known/"))], sent)


class StrictFilterDriveTests(CoverageDriveCallerTests):
    strict = True
    well_known = False

    def test_drive_confirms_each_cell_and_keeps_its_negatives(self):
        cells, findings, _sent = self.drive()
        rows = self.rows(cells, "AV-FILTER-01", "/files")
        self.assertEqual({r["observation_status"] for r in rows}, {CellStatus.NOT_DETECTED.value}, rows)
        self.assertFalse([f for f in findings if f.get("confirmed_by_leg") == "filter_bypass_validator"])
        # No security.txt: the origin cell is a negative, not an observation.
        self.assertFalse([f for f in findings if f.get("confirmed_by_leg") == "well_known_validator"])

    test_disabled_legs_are_unavailable_and_send_nothing = None


if __name__ == "__main__":
    unittest.main()
