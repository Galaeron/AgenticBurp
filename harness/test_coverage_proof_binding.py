"""Coverage-drive proofs reach the stored findings (r10, job 9eb242afd5a0).

r10 confirmed 19 AV-EXPOSURE-01 (content_exposure_validator) proofs, plus 124 csp
and security-headers proofs, in the engagement coverage drive. Each proof was
persisted and its finding went into engagement state, but the drive never bound
the proof to the store's findings table. Every stored row on those routes stayed
unconfirmed, and the report, which reads that table, showed none of them. The
graph loop binds its proofs (r5, store.bind_confirmation_proof); the coverage drive
now does too, narrowed because its proofs were not run for any stored row:

- A confirmed proof upgrades an unconfirmed row on the same method and normalized
  route, of its own class, recorded under the same principal, that the proving
  validator speaks for (its own `applies` routing). Otherwise it creates a row of
  its own class that carries the proof's evidence.
- A broad-class row the validator does not route stays as it was. AV-EXPOSURE-01
  routes no agent finding, so it never upgrades a PII info_disclosure row.
- An inconclusive, skipped or not_confirmed proof binds nothing.

Production caller: Orchestrator.investigate_engagement's coverage drive over a
loopback fixture (the exposure-leads app). Every send stays on 127.0.0.1.
"""
import asyncio
import os
import shutil
import sqlite3
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import AsyncMock, patch

from harness import cache, global_throttle, safety_gate, store
from harness.evidence import ProofRecord, TestCaseRef
from harness.models import Finding, HttpExchange
from harness.test_exposure_leads import _App
from harness.validators.base import ValidationResult

_DRIVEN = ("/files", "/metrics", "/status", "/page")
_OTHER_PRINCIPAL = {"Authorization": "Bearer another-principal"}


def _row(cls, *, verdict=None, case="", summary="seeded claim", parameter_name=""):
    return Finding(vulnerability_class=cls, confidence=0.4, severity="medium", summary=summary,
                   evidence="seeded evidence", suggested_test="verify", basis="derived",
                   review_verdict=verdict, case_id=case, parameter_name=parameter_name,
                   parameter_location="query" if parameter_name else "")


class _LoopbackCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="coverage_binding_")
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
        self.server.strict = False
        self.server.well_known = False
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        store._DB_PATH, cache._cache = self._saved
        safety_gate.reset_default_gate()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def capture(self, path):
        import urllib.request
        try:
            with urllib.request.urlopen(self.origin + path) as resp:
                status, headers, body = resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as err:
            status, headers, body = err.code, dict(err.headers), err.read()
        self.server.received.clear()
        return HttpExchange(url=self.origin + path, method="GET", response_status=status,
                            response_headers=headers, response_body=body.decode("utf-8", errors="replace"))

    def seed(self, path, finding, headers=None, method="GET"):
        ex = HttpExchange(url=self.origin + path, method=method, request_headers=dict(headers or {}),
                          response_status=200)
        store.persist_findings(ex, "seeded_agent", [finding])

    def rows(self, path=None):
        rows = store.all_host_findings(self.origin + "/")
        return [r for r in rows if path is None or r["url"] == self.origin + path]

    def drive(self, families, validate=None):
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
        for name in families:
            cfg["validators"][name]["enabled"] = True
        orch = Orchestrator(cfg)
        _controlled_model(orch)
        orch.business_context_enabled = False
        orch.engagement_coverage_drive = True
        orch.engagement_coverage_case_drive = True
        orch.run_active_probe = AsyncMock(return_value={"iterative_result": {"findings": []}, "integration": {}})
        if validate is not None:
            for name in families:
                orch.validator_registry.validators[name].validate = validate
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
            return asyncio.run(run())

    def proofs(self):
        conn = sqlite3.connect(store._DB_PATH)
        try:
            return conn.execute("SELECT validator, verdict, legacy, executed, finding_ref "
                                "FROM proof_records").fetchall()
        finally:
            conn.close()


class CoverageProofCallerTests(_LoopbackCase):
    def test_legacy_content_exposure_proof_becomes_a_confirmed_finding_of_its_class(self):
        # r10's shape: the routes already hold unconfirmed rows from other agents.
        self.seed("/metrics", _row("info_disclosure", summary="Confidential information (pii)",
                                   case="seed-pii"))
        self.seed("/metrics", _row("broken_authentication", case="seed-auth"))
        self.seed("/status", _row("info_disclosure", case="seed-status"))
        result = self.drive(("content_exposure",))
        self.assertTrue([f for f in result["findings"]
                         if f.get("confirmed_by_leg") == "content_exposure_validator"])

        mine = [r for r in self.rows() if r["agent"] == "content_exposure_validator"]
        by_path = {r["url"][len(self.origin):]: r for r in mine}
        # The listing and the exposition confirm; /status and /page hold.
        self.assertEqual(set(by_path), {"/files", "/metrics"}, mine)
        metrics = by_path["/metrics"]
        self.assertEqual((metrics["vulnerability_class"], metrics["confirmed"]), ("info_disclosure", True))
        self.assertEqual(metrics["proof_status"], "resolved")
        self.assertEqual(metrics["review_verdict"], "validator-confirmed")
        self.assertEqual(metrics["captured_principal_id"], "anonymous")
        self.assertIn("metrics_exposition", metrics["evidence"])
        proof = [p for p in store.proofs_for_case(metrics["case_id"]) if p["proof_id"] == metrics["proof_id"]]
        self.assertEqual([(p["verdict"], p["legacy"], p["executed"]) for p in proof],
                         [("confirmed", True, True)], "a legacy (artifact-free) passive proof")

        # The report reads the store: the exposure is now a confirmed issue.
        from harness.report_generator import export_issues_for_host
        confirmed = [i for i in export_issues_for_host(self.origin + "/")
                     if i["evidence_state"] == "confirmed"]
        self.assertTrue([i for i in confirmed if i["vulnerability_class"] == "info_disclosure"
                         and i["endpoint_family"] == "/metrics"], confirmed)

        # Negative controls: AV-EXPOSURE-01 routes no agent finding, so a PII row of
        # the same broad class is not its claim; another class and another route
        # stay unconfirmed too, and a not_confirmed route gains nothing.
        seeded = {(r["url"][len(self.origin):], r["vulnerability_class"]): r
                  for r in self.rows() if r["agent"] == "seeded_agent"}
        self.assertEqual(len(seeded), 3)
        self.assertFalse(any(r["confirmed"] for r in seeded.values()), seeded)
        self.assertEqual(seeded[("/metrics", "info_disclosure")]["evidence"], "seeded evidence")
        self.assertFalse([r for r in self.rows("/status") if r["confirmed"]])

    def test_routed_proof_upgrades_only_its_own_claim(self):
        # metrics_exposure_validator routes info_disclosure leads on an exposition.
        self.seed("/metrics", _row("info_disclosure", verdict="downgraded", case="seed-anon"))
        self.seed("/metrics", _row("info_disclosure", case="seed-other"), headers=_OTHER_PRINCIPAL)
        self.seed("/metrics", _row("broken_authentication", case="seed-auth"))
        self.seed("/metrics", _row("info_disclosure", case="seed-post"), method="POST")
        self.seed("/metrics/history", _row("info_disclosure", case="seed-prefix"))
        self.seed("/status", _row("info_disclosure", case="seed-status"))
        self.drive(("metrics_exposure",))

        rows = {r["case_id"] if r["agent"] == "seeded_agent" else r["agent"]: r for r in self.rows()}
        upgraded = [r for r in self.rows() if r["agent"] == "seeded_agent" and r["confirmed"]]
        self.assertEqual(len(upgraded), 1, upgraded)
        bound = upgraded[0]
        self.assertEqual((bound["url"], bound["vulnerability_class"], bound["captured_principal_id"]),
                         (self.origin + "/metrics", "info_disclosure", "anonymous"))
        self.assertEqual(bound["proof_status"], "resolved")
        self.assertEqual(bound["validator"], "metrics_exposure_validator")
        # Review precedence (PASS1): the proof outranks the demoting verdict, and the
        # superseded verdict stays on record.
        self.assertEqual(bound["review_verdict"], "validator-confirmed")
        self.assertIn("prior review verdict 'downgraded' superseded by metrics_exposure_validator",
                      bound["evidence"])
        self.assertIn("metrics_exposure_validator CONFIRMED:", bound["evidence"])
        self.assertNotIn("metrics_exposure_validator", rows, "a matching row was upgraded, none added")
        # Negative controls: another principal, another class, another method, a
        # route that only shares the path prefix, and another route.
        for case in ("seed-other", "seed-auth", "seed-post", "seed-prefix", "seed-status"):
            self.assertFalse(rows[case]["confirmed"], (case, rows[case]))
        self.assertTrue(rows["seed-other"]["captured_principal_id"].startswith("captured:"))

    def test_inconclusive_proof_binds_nothing(self):
        self.seed("/metrics", _row("info_disclosure", case="seed-anon"))

        async def inconclusive(finding, exchange):
            return ValidationResult("metrics_exposure_validator", "inconclusive", finding.vulnerability_class,
                                    confidence=0.5, summary="fixture: the control could not be read")
        self.drive(("metrics_exposure",), validate=inconclusive)
        self.assertIn(("metrics_exposure_validator", "inconclusive"), {p[:2] for p in self.proofs()})
        self.assertFalse([r for r in self.rows() if r["confirmed"]], self.rows())
        self.assertEqual([r["case_id"] for r in self.rows()], ["seed-anon"], "no row added")


class BindingSeamTests(_LoopbackCase):
    """store.bind_confirmation_proof's coverage keywords, without a drive."""

    def proven(self, path, cls="info_disclosure", headers=None, **kw):
        ex = HttpExchange(url=self.origin + path, method="GET", request_headers=dict(headers or {}))
        case = TestCaseRef.make(run_id="r10", request_template_id=path, check_id="AV-EXPOSURE-03",
                                principal_id="eval-user-1" if headers else "anonymous")
        pr = ProofRecord.from_validation_result(case=case, validator="metrics_exposure_validator",
                                                status="confirmed", confirmed=True)
        ok, reason = store.persist_proof_record(pr)
        self.assertTrue(ok, reason)
        finding = Finding(vulnerability_class=cls, confidence=0.95, severity="medium",
                          summary="proof summary", evidence="proof evidence", suggested_test="",
                          basis="derived", review_verdict="validator-confirmed", confirmed=True,
                          proof_id=pr.proof_id, case_id=case.case_id)
        return ex, finding

    def bind(self, ex, finding, **kw):
        kw.setdefault("principal_bound", True)
        kw.setdefault("accepts_class", lambda cls: True)
        return store.bind_confirmation_proof(ex, finding, "metrics_exposure_validator", **kw)

    def test_principal_bound_proof_keeps_its_principal(self):
        self.seed("/metrics", _row("info_disclosure", case="seed-anon"))
        ex, finding = self.proven("/metrics", headers=_OTHER_PRINCIPAL)
        self.assertEqual(self.bind(ex, finding), 1)
        rows = self.rows("/metrics")
        anon = [r for r in rows if r["case_id"] == "seed-anon"]
        self.assertFalse(anon[0]["confirmed"], "an authenticated proof never confirms the anonymous row")
        created = [r for r in rows if r["agent"] == "metrics_exposure_validator"]
        self.assertEqual(len(created), 1)
        self.assertTrue(created[0]["confirmed"])
        self.assertEqual(created[0]["captured_principal_id"], store.captured_principal_id(ex))
        # Bound again: the proof's own row already stands; nothing is added.
        self.assertEqual(self.bind(ex, finding), 0)
        self.assertEqual(len(self.rows("/metrics")), 2)

    def test_normalized_route_matches_query_values_not_names(self):
        self.seed("/items?id=1", _row("info_disclosure", case="seed-value"))
        self.seed("/items?name=x", _row("info_disclosure", case="seed-name"))
        self.seed("/items/1", _row("info_disclosure", case="seed-path"))
        ex, finding = self.proven("/items?id=2")
        self.assertEqual(self.bind(ex, finding), 1)
        confirmed = {r["case_id"] for r in self.rows() if r["confirmed"]}
        self.assertEqual(confirmed, {finding.case_id})
        self.assertEqual([r["url"] for r in self.rows() if r["confirmed"]], [self.origin + "/items?id=1"])

    def test_unrouted_class_gets_its_own_row(self):
        self.seed("/metrics", _row("info_disclosure", case="seed-anon"))
        ex, finding = self.proven("/metrics")
        self.assertEqual(self.bind(ex, finding, accepts_class=lambda cls: False), 1)
        rows = self.rows("/metrics")
        self.assertFalse([r for r in rows if r["case_id"] == "seed-anon" and r["confirmed"]])
        self.assertEqual([r["agent"] for r in rows if r["confirmed"]], ["metrics_exposure_validator"])

    def test_same_identity_duplicates_bind_once(self):
        # Two unconfirmed rows of one fingerprint: only one can carry the proof's case.
        self.seed("/metrics", _row("info_disclosure", case="seed-a"))
        self.seed("/metrics", _row("info_disclosure", case="seed-b"))
        ex, finding = self.proven("/metrics")
        self.assertEqual(self.bind(ex, finding), 1)
        self.assertEqual(sum(r["confirmed"] for r in self.rows("/metrics")), 1)

    def test_unconfirmed_finding_binds_nothing(self):
        self.seed("/metrics", _row("info_disclosure", case="seed-anon"))
        ex, finding = self.proven("/metrics")
        self.assertEqual(self.bind(ex, finding.model_copy(update={"confirmed": False})), 0)
        self.assertFalse([r for r in self.rows() if r["confirmed"]])


if __name__ == "__main__":
    unittest.main()
