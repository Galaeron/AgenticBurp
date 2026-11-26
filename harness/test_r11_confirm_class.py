"""R11-1: a confirmation counts only for the class whose mechanism it proves.

r11: findings of unrelated classes rode two shape-routed legs to "confirmed" --
a published security.txt confirmed sqli/xss/jwt rows on /.well-known/*, and a
password digest in the caller's own response confirmed xss/sqli/idor rows on
the same route. Here, through the production caller
(Orchestrator._validate_findings with the real registry, plus the plan path
plan_dispatch.dispatch_plans) against owned loopback services:

* a wrong-class finding keeps its own verdict, and the proof is filed once as a
  finding of the class it proves (an info observation for .well-known);
* the controls still confirm: a .well-known finding gets its observation, a data
  exposure finding on the digest route confirms, and another account's secret
  still proves a BOLA (the r7 path);
* removing the gate (proves_finding_class -> True) brings the r11 rows back.

Fixtures are generic owned services and synthetic values.
"""
import asyncio
import hashlib
from dataclasses import dataclass, field
import json
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from harness import cache, global_throttle, planner, plan_dispatch, safety_gate, store
from harness.models import AgentReport, Finding, HttpExchange
from harness.orchestrator import Orchestrator
from harness.run_context import RunContext
from harness.test_default_history_caller import _config, _RecordingModel
from harness.validators.base import ValidationResult, Validator, proves_finding_class

_DIGEST = hashlib.md5(b"r11-fixture").hexdigest()
# The caller's (alice's) own record, carrying her stored password digest.
OWN_DIGEST = {"id": 1, "username": "alice", "email": "a@example.test", "passwordHash": _DIGEST}
# Another account's (bob's) record, read as alice.
OTHER_DIGEST = {"id": 2, "username": "bob", "email": "b@example.test", "passwordHash": _DIGEST}


class _Service(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body, ctype):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        self.server.received.append(path)
        if path == "/.well-known/security.txt":
            return self.reply(200, b"Contact: mailto:security@fixture.test\n"
                                   b"Expires: 2030-01-01T00:00:00Z\n", "text/plain")
        if path.startswith("/api/"):
            if not self.headers.get("Authorization"):
                return self.reply(401, b'{"error": "login required"}', "application/json")
            return self.reply(200, json.dumps(self.server.doc).encode(), "application/json")
        return self.reply(404, b"Not found", "text/plain")


def _finding(cls, evidence="capture"):
    return Finding(vulnerability_class=cls, confidence=0.6, severity="high", summary="lead",
                   evidence=evidence, suggested_test="replay", basis="derived")


class _Base(unittest.TestCase):
    validators = ()

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="r11_class_")
        self._saved = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()
        st = global_throttle.throttle.stats()
        prev = (st["rate_per_second"] if st["enabled"] else 0.0, st["burst"] if st["enabled"] else None)
        self.addCleanup(lambda: global_throttle.configure(*prev))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Service)
        self.server.received, self.server.doc = [], OWN_DIGEST
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        store._DB_PATH, cache._cache = self._saved
        safety_gate.reset_default_gate()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def orch(self):
        cfg = _config()
        cfg["server"]["allowed_hosts"] = ["127.0.0.1"]
        cfg["validators"].update(active_enabled=True)
        orch = Orchestrator(cfg)
        model = _RecordingModel()
        orch.ollama = model
        for agent in orch.agent_manager.agents.values():
            agent.ollama = model
        global_throttle.configure(0)
        orch.validator_registry.validators = {
            k: v for k, v in orch.validator_registry.validators.items() if k in self.validators}
        self.assertEqual(set(orch.validator_registry.validators), set(self.validators))
        return orch, cfg

    def run_with(self, cfg, body):
        async def go():
            run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=100, config=cfg,
                                    gate_config={"active_enabled": True})
            run.sessions.register("a", "alice", {"Authorization": "Bearer a"},
                                  allowed_origins=[self.origin])
            run.sessions.register("b", "bob", {"Authorization": "Bearer b"},
                                  allowed_origins=[self.origin])
            async with run:
                out = await body(run)
            await run.aclose()
            return out
        return asyncio.run(go())

    def validate(self, exchange, findings, agent="injection"):
        orch, cfg = self.orch()
        reports = [AgentReport(agent=agent, model="fake", findings=list(findings))]

        async def body(run):
            return await orch._validate_findings(exchange, reports, run_context=run)
        validations, proofs = self.run_with(cfg, body)
        return reports, validations, proofs

    @staticmethod
    def filed(reports):
        """Findings the dispatcher filed apart (reports it appended)."""
        return [f for r in reports[1:] for f in r.findings]


class WellKnownClassTests(_Base):
    validators = ("well_known",)

    def exchange(self):
        return HttpExchange(url=self.origin + "/.well-known/security.txt?q=1", method="GET",
                            response_status=200, response_headers={"Content-Type": "text/plain"},
                            response_body="Contact: mailto:security@fixture.test\n")

    def test_sqli_on_security_txt_is_not_confirmed_and_files_one_observation(self):
        sqli = _finding("sqli")
        reports, validations, proofs = self.validate(self.exchange(), [sqli])
        self.assertFalse(sqli.confirmed)
        self.assertEqual(sqli.proof_id, "")
        self.assertIsNone(sqli.review_verdict)
        mine = [v for v in validations if v.finding_class == "sqli"]
        self.assertEqual([(v.status, v.confirmed) for v in mine], [("skipped", False)])
        self.assertIn("not this finding's class", mine[0].summary)
        filed = self.filed(reports)
        self.assertEqual(len(filed), 1, filed)
        obs = filed[0]
        self.assertEqual(obs.vulnerability_class, "security_txt")
        self.assertEqual(obs.severity, "info")
        self.assertTrue(obs.confirmed)
        self.assertEqual(obs.confirmed_by_leg, "well_known_validator")
        self.assertTrue(obs.proof_id)
        self.assertIn(obs.proof_id, [p["proof_id"] for p in proofs])
        self.assertIn("Observation (not a vulnerability)", obs.summary)
        self.assertEqual(reports[1].agent, "well_known_validator")

    def test_several_wrong_class_findings_file_one_observation(self):
        found = [_finding(c) for c in ("sqli", "xss", "jwt", "command_injection")]
        reports, _validations, _ = self.validate(self.exchange(), found)
        self.assertFalse(any(f.confirmed for f in found))
        self.assertEqual([f.vulnerability_class for f in self.filed(reports)], ["security_txt"])

    def test_control_well_known_finding_gets_its_observation(self):
        lead = _finding("security.txt")
        reports, validations, _ = self.validate(self.exchange(), [lead], agent="recon")
        self.assertTrue(lead.confirmed, [(v.status, v.summary) for v in validations])
        self.assertEqual(lead.confirmed_by_leg, "well_known_validator")
        self.assertEqual(self.filed(reports), [])
        self.assertEqual(len(reports), 1)

    def test_defect_injection_without_the_gate_sqli_confirms(self):
        with patch("harness.orchestrator_confirm.proves_finding_class", return_value=True):
            sqli = _finding("sqli")
            reports, _validations, _ = self.validate(self.exchange(), [sqli])
        self.assertTrue(sqli.confirmed, "the gate is what keeps the r11 row out")
        self.assertEqual(self.filed(reports), [])


class ExposureClassTests(_Base):
    validators = ("api_security",)

    def exchange(self, doc):
        self.server.doc = doc
        return HttpExchange(url=self.origin + "/api/profile?q=1", method="GET",
                            request_headers={"Authorization": "Bearer a"}, response_status=200,
                            response_headers={"Content-Type": "application/json"},
                            response_body=json.dumps(doc))

    def test_xss_on_a_digest_route_files_one_exposure_and_no_xss(self):
        xss = _finding("xss")
        reports, validations, _ = self.validate(self.exchange(OWN_DIGEST), [xss])
        self.assertFalse(xss.confirmed)
        self.assertIsNone(xss.review_verdict)
        self.assertFalse([v for v in validations if v.finding_class == "xss" and v.confirmed])
        filed = self.filed(reports)
        self.assertEqual(len(filed), 1, filed)
        self.assertEqual(filed[0].vulnerability_class, "excessive data exposure")
        self.assertTrue(filed[0].confirmed)
        self.assertEqual(filed[0].confirmed_by_leg, "api_security_validator")
        self.assertIn("own credential secret", filed[0].evidence)
        self.assertNotIn(_DIGEST, filed[0].evidence + filed[0].summary)
        self.assertEqual(filed[0].severity, "high")

    def test_wrong_class_rows_on_one_route_file_one_exposure(self):
        found = [_finding(c) for c in ("xss", "sqli", "jwt", "BOLA")]
        reports, _validations, _ = self.validate(self.exchange(OWN_DIGEST), found)
        self.assertFalse(any(f.confirmed for f in found),
                         [(f.vulnerability_class, f.confirmed) for f in found])
        self.assertEqual(len(self.filed(reports)), 1)

    def test_control_data_exposure_finding_on_the_route_confirms(self):
        for label in ("Sensitive Data Exposure", "excessive data exposure", "information disclosure"):
            with self.subTest(label=label):
                lead = _finding(label)
                reports, validations, _ = self.validate(self.exchange(OWN_DIGEST), [lead])
                self.assertTrue(lead.confirmed, [(v.status, v.summary) for v in validations])
                self.assertEqual(lead.confirmed_by_leg, "api_security_validator")
                self.assertEqual(self.filed(reports), [])

    def test_control_another_accounts_secret_still_proves_bola(self):
        bola = _finding("Broken Object-Level Authorization (BOLA)")
        reports, validations, _ = self.validate(self.exchange(OTHER_DIGEST), [bola], agent="idor")
        self.assertTrue(bola.confirmed, [(v.status, v.summary) for v in validations])
        self.assertEqual(self.filed(reports), [])

    def test_defect_injection_without_the_gate_xss_confirms(self):
        with patch("harness.orchestrator_confirm.proves_finding_class", return_value=True):
            xss = _finding("xss")
            reports, _validations, _ = self.validate(self.exchange(OWN_DIGEST), [xss])
        self.assertTrue(xss.confirmed)
        self.assertEqual(self.filed(reports), [])

    def test_plan_path_keeps_the_filed_exposure_with_the_callers_reports(self):
        """The worklist route: plans -> dispatch_plans -> _validate_findings."""
        orch, cfg = self.orch()
        ex = self.exchange(OWN_DIGEST)
        xss = _finding("xss")
        own = store.persist_test_plans(ex, planner.plans_for_findings(ex, [xss]))
        self.assertIn("api_security_validation", [p.capability for p in own])
        reports = [AgentReport(agent="xss", model="fake", findings=[xss])]

        async def body(run):
            validations: list = []
            await plan_dispatch.dispatch_plans(orch, ex, own, reports, validations, run_context=run)
            return validations
        self.run_with(cfg, body)
        self.assertFalse(xss.confirmed)
        filed = self.filed(reports)
        self.assertEqual([f.vulnerability_class for f in filed], ["excessive data exposure"])
        self.assertTrue(filed[0].confirmed)


@dataclass
class _IterativeResult:
    agent: str = "iterative:injection"
    findings: list = field(default_factory=list)
    handoff_note: str = ""
    stop_reason: str = "found"


class IterativeReviewPathTests(_Base):
    """The iterative agent's route: pivot_memory.integrate -> review ->
    _review_iterative_findings -> plan dispatch -> _validate_findings, then the held
    findings persist. An xss finding on a route returning the caller's own digest
    earns the exposure plan by evidence; its proof is a data exposure, not xss."""
    validators = ("api_security",)

    def integrate(self, findings, review_list=lambda held: held):
        from harness import pivot_memory
        orch, cfg = self.orch()
        self.server.doc = OWN_DIGEST
        ex = HttpExchange(url=self.origin + "/api/profile?q=1", method="GET",
                          request_headers={"Authorization": "Bearer a"}, response_status=200,
                          response_headers={"Content-Type": "application/json"},
                          response_body=json.dumps(OWN_DIGEST))

        async def body(run):
            async def review(held, plans):
                self.assertIn("api_security_validation", [p.capability for p in plans])
                await orch._review_iterative_findings(ex, "injection", review_list(held), plans,
                                                      run_context=run)
            return await pivot_memory.integrate(_IterativeResult(findings=list(findings)), ex,
                                                review=review)
        out = self.run_with(cfg, body)
        return out, store.all_host_findings(ex.url)

    def test_split_off_finding_is_stored_with_its_proof(self):
        out, rows = self.integrate([_finding("xss")])
        xss = [f for f in out.held_findings if f.vulnerability_class == "xss"]
        self.assertEqual(len(xss), 1)
        self.assertFalse(xss[0].confirmed)
        self.assertEqual(xss[0].proof_id, "")
        stored = [r for r in rows if r["vulnerability_class"] == "excessive data exposure"]
        self.assertEqual(len(stored), 1, [(r["vulnerability_class"], r.get("proof_id")) for r in rows])
        self.assertTrue(stored[0]["confirmed"])
        self.assertTrue(stored[0]["proof_id"])
        bound = [pr for pr in store.proofs_for_case(stored[0]["case_id"])
                 if pr["proof_id"] == stored[0]["proof_id"]]
        self.assertEqual(len(bound), 1, stored[0])
        self.assertEqual(bound[0]["verdict"], "confirmed")
        self.assertEqual(bound[0]["case"]["finding_ref"], stored[0]["finding_id"])
        self.assertEqual(bound[0]["validator"], "api_security_validator")
        stored_xss = [r for r in rows if r["vulnerability_class"] == "xss"]
        self.assertEqual(len(stored_xss), 1)
        self.assertFalse(stored_xss[0]["confirmed"])
        self.assertFalse(stored_xss[0]["proof_id"])

    def test_defect_injection_a_review_on_a_copy_orphans_the_proof(self):
        """The pre-fix behaviour: the filed finding never reaches the held list."""
        _out, rows = self.integrate([_finding("xss")], review_list=list)
        self.assertEqual([r for r in rows if r["vulnerability_class"] == "excessive data exposure"], [])


class JwtResetTokenClassTests(_Base):
    """jwt_forge still runs on a reset-token finding (applies() routes it through the
    weak_token declaration), but its confirmation is not that finding's proof."""
    validators = ("jwt_forge",)

    def exchange(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2ln"
        return HttpExchange(url=self.origin + "/api/reset?q=1", method="GET",
                            request_headers={"Authorization": f"Bearer {token}"},
                            response_status=200, response_body="{}")

    def validate_forged(self, finding):
        async def forged(leg, f, ex):
            return ValidationResult("jwt_forge", "confirmed", f.vulnerability_class,
                                    confirmed=True, confidence=0.95, summary="forged token accepted")
        with patch("harness.validators.jwt_forge_validator.JwtForgeValidator.validate", forged):
            return self.validate(self.exchange(), [finding], agent="auth")

    def test_reset_token_finding_is_routed_but_not_confirmed(self):
        from harness.validators.jwt_forge_validator import JwtForgeValidator
        for label in ("reset_token", "weak_token", "reset token"):
            with self.subTest(label=label):
                lead = _finding(label)
                self.assertTrue(JwtForgeValidator().applies(lead, self.exchange()))
                reports, validations, _ = self.validate_forged(lead)
                self.assertEqual([v.validator for v in validations][:1], ["jwt_forge"])
                self.assertFalse(lead.confirmed)
                self.assertEqual([f.vulnerability_class for f in self.filed(reports)], ["jwt"])

    def test_control_jwt_finding_still_confirms(self):
        for label in ("jwt", "JWT None Algorithm", "broken_authentication"):
            with self.subTest(label=label):
                lead = _finding(label)
                reports, _validations, _ = self.validate_forged(lead)
                self.assertTrue(lead.confirmed)
                self.assertEqual(lead.confirmed_by_leg, "jwt_forge")
                self.assertEqual(self.filed(reports), [])


class _Shape(Validator):
    """Routes by exchange shape whatever the class; its result proves `proves`."""
    name = "shape_leg"
    finding_classes = {"open_redirect"}

    def __init__(self, proves=(), observation=False):
        self.proves, self.observation = proves, observation

    def applies(self, finding, exchange):
        return True

    def claims_class(self, finding, exchange=None):
        return Validator.applies(self, finding, exchange)

    async def validate(self, finding, exchange):
        return ValidationResult(self.name, "confirmed", finding.vulnerability_class,
                                confirmed=True, confidence=0.9, summary="proof",
                                mechanism_classes=self.proves, observation=self.observation)


class BindingRuleTests(unittest.TestCase):
    """The rule itself, on the result a shape-routed leg returns."""

    def decide(self, cls, **kw):
        leg = _Shape(**kw)
        result = asyncio.run(leg.validate(_finding(cls), None))
        return proves_finding_class(leg, result, _finding(cls), None)

    def test_rule(self):
        self.assertTrue(self.decide("open redirect"))                   # claimed class
        self.assertFalse(self.decide("sqli"))                           # shape only
        self.assertTrue(self.decide("idor", proves=("idor",)))           # result's mechanism
        self.assertTrue(self.decide("bola", proves=("idor",)))           # same issue class
        self.assertFalse(self.decide("xss", proves=("idor",)))
        # (b) an observation never confirms a vulnerability class, even a claimed one
        self.assertFalse(self.decide("open_redirect", observation=True))
        self.assertTrue(self.decide("recon", proves=("recon",), observation=True))

    def test_duck_typed_validator_keeps_its_routing(self):
        class Duck:
            def applies(self, finding, exchange):
                return True
        result = ValidationResult("duck", "confirmed", "x", confirmed=True)
        self.assertTrue(proves_finding_class(Duck(), result, _finding("sqli")))


if __name__ == "__main__":
    unittest.main()
