"""r7 follow-up: the sensitive-field exposure oracle is reached by response
evidence, not only by the "excessive data exposure" label.

r7 (8h live run): the real exposures arrived labelled BOLA/BFLA, so they went to
cross_identity only. Here a finding of any class on a captured GET whose
response holds an unmasked allowlisted secret also reaches the oracle, through
the production callers:

* the plan path (planner.plans_for_findings -> store.persist_test_plans ->
  plan_dispatch.dispatch_plans -> Orchestrator._validate_findings), which the
  worklist review uses;
* the analyze path (Orchestrator._validate_findings with registry routing);
* the capture sweep (Orchestrator.analyze on a capture no agent flagged).

Plus the access-matrix expectation: an operator answer that the caller may read
the object type stops a confirmation on another account's object.

Fixtures are a generic owned loopback JSON service and synthetic values.
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

from harness import cache, global_throttle, planner, plan_dispatch, safety_gate, store
from harness.models import AgentReport, Finding, HttpExchange
from harness.orchestrator import Orchestrator
from harness.run_context import RunContext
from harness.test_default_history_caller import _config, _RecordingModel
from harness.validators.api_security_validator import ApiSecurityValidator, exposure_evidence
from harness.validators.base import ValidationResult, Validator

BOLA = "Broken Object-Level Authorization (BOLA)"
# Another account's (bob's) object, read by alice: a stored password hash.
OTHER_HASH = {"id": 2, "username": "bob", "email": "b@example.test",
              "passwordHash": "5f4dcc3b5aa765d61d8327deb882cf99"}
NO_SECRET = {"id": 2, "username": "bob", "email": "b@example.test", "role": "user"}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.received.append(dict(self.headers))
        if not self.headers.get("Authorization"):
            body, status = b'{"error": "login required"}', 401
        else:
            body, status = json.dumps(self.server.doc).encode(), 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _CrossStub(Validator):
    """Stands in for the access-control leg the BOLA class normally earns, so a
    test can show the oracle runs in addition to it. Sends nothing."""
    name = "cross_identity"
    finding_classes = {"idor"}
    # Active like the real leg (a passive one is re-run by the passive oracle).
    active = True

    def __init__(self):
        # A list, not a counter: the registry dispatches shallow copies.
        self.log: list = []

    def get_name(self):
        return "cross_identity"

    async def validate(self, finding, exchange):
        self.log.append(finding.vulnerability_class)
        return ValidationResult("cross_identity", "not_confirmed", finding.vulnerability_class,
                                summary="stub")


def _finding(cls=BOLA, evidence="other user's record returned"):
    return Finding(vulnerability_class=cls, confidence=0.6, severity="high",
                   summary="object of another user readable", evidence=evidence,
                   suggested_test="compare owners", basis="observed")


class _Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="r7exp_")
        self._saved = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()
        st = global_throttle.throttle.stats()
        prev = (st["rate_per_second"] if st["enabled"] else 0.0, st["burst"] if st["enabled"] else None)
        self.addCleanup(lambda: global_throttle.configure(*prev))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.received = []
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.url = self.origin + "/api/accounts/2"
        self.cross = _CrossStub()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        store._DB_PATH, cache._cache = self._saved
        safety_gate.reset_default_gate()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _orch(self):
        cfg = _config()
        cfg["server"]["allowed_hosts"] = ["127.0.0.1"]
        cfg["validators"].update(active_enabled=True)
        orch = Orchestrator(cfg)
        model = _RecordingModel()
        orch.ollama = model
        for agent in orch.agent_manager.agents.values():
            agent.ollama = model
        global_throttle.configure(0)
        orch.validator_registry.validators = {"api_security": ApiSecurityValidator(),
                                              "cross_identity": self.cross}
        return orch, cfg

    def _exchange(self, captured_doc):
        return HttpExchange(url=self.url, method="GET",
                            request_headers={"Authorization": "Bearer a"}, response_status=200,
                            response_headers={"Content-Type": "application/json"},
                            response_body=json.dumps(captured_doc))

    def _run(self, orch, cfg, body):
        async def go():
            run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=50, config=cfg,
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


class EvidenceRoutingPlanPathTests(_Base):
    """The worklist-review route: plans -> dispatch_plans -> _validate_findings."""

    def dispatch(self, captured_doc, live_doc=None, finding=None):
        self.server.doc = captured_doc if live_doc is None else live_doc
        orch, cfg = self._orch()
        ex = self._exchange(captured_doc)
        f = finding or _finding()
        plans = planner.plans_for_findings(ex, [f])
        own = store.persist_test_plans(ex, plans)

        async def body(run):
            reports: list = []
            summary = await plan_dispatch.dispatch_plans(
                orch, ex, own, [AgentReport(agent="idor", model="fake", findings=[f])], reports,
                run_context=run)
            return reports, summary
        reports, summary = self._run(orch, cfg, body)
        return plans, reports, summary

    def test_bola_finding_carrying_another_accounts_hash_reaches_the_oracle_and_confirms(self):
        plans, reports, summary = self.dispatch(OTHER_HASH)
        caps = sorted(p.capability for p in plans)
        # In addition to, not instead of, the access-control plan its class earns.
        self.assertIn("api_security_validation", caps)
        self.assertIn("cross_identity_compare", caps)
        mine = [r for r in reports if r.validator == "api_security_validator"]
        self.assertEqual(len(mine), 1, [(r.validator, r.status) for r in reports])
        self.assertEqual(mine[0].status, "confirmed", mine[0].summary)
        self.assertEqual(mine[0].finding_class, BOLA)
        self.assertIn("field=$.passwordHash", mine[0].evidence)
        self.assertIn("owner=bob; reader=alice", mine[0].evidence)
        self.assertNotIn(OTHER_HASH["passwordHash"], mine[0].evidence)
        self.assertEqual(self.cross.log, [BOLA], "the class's own validator must still run")
        # baseline + repeat as alice, anonymous control.
        self.assertEqual([h.get("Authorization") for h in self.server.received],
                         ["Bearer a", "Bearer a", None])
        self.assertEqual(len(summary["dispatched"]), 2, summary)

    def test_removing_evidence_routing_loses_the_confirmation(self):
        """Defect injection: without the evidence signal the BOLA label reaches
        cross_identity only, as in r7, so the positive case is not vacuous."""
        from unittest.mock import patch
        with patch("harness.validators.api_security_validator.exposure_evidence",
                   return_value=[]):
            plans, reports, _ = self.dispatch(OTHER_HASH)
        self.assertNotIn("api_security_validation", [p.capability for p in plans])
        self.assertEqual([r.validator for r in reports], ["cross_identity"])

    def test_secret_named_only_in_the_findings_evidence_body_routes(self):
        f = _finding(evidence="response excerpt: " + json.dumps(OTHER_HASH))
        plans, reports, _ = self.dispatch(NO_SECRET, live_doc=OTHER_HASH, finding=f)
        self.assertIn("api_security_validation", [p.capability for p in plans])
        mine = [r for r in reports if r.validator == "api_security_validator"]
        self.assertEqual([r.status for r in mine], ["confirmed"])

    def test_bola_finding_without_a_sensitive_field_is_not_routed(self):
        plans, reports, _ = self.dispatch(NO_SECRET)
        self.assertNotIn("api_security_validation", [p.capability for p in plans])
        self.assertEqual([r for r in reports if r.validator == "api_security_validator"], [])
        self.assertEqual(self.cross.log, [BOLA])
        self.assertEqual(self.server.received, [])

    def test_masked_fields_do_not_route_or_confirm(self):
        for value in ("****", None, "", "[redacted]"):
            with self.subTest(value=value):
                self.server.received.clear()
                doc = dict(OTHER_HASH, passwordHash=value)
                plans, reports, _ = self.dispatch(doc)
                self.assertNotIn("api_security_validation", [p.capability for p in plans])
                self.assertFalse([r for r in reports if r.confirmed])
                self.assertEqual(self.server.received, [])

    def test_replay_that_masks_the_field_is_not_confirmed(self):
        # The capture carried the value, the live answer masks it: routed, but the
        # oracle decides on its own replay.
        plans, reports, _ = self.dispatch(OTHER_HASH, live_doc=dict(OTHER_HASH, passwordHash="****"))
        mine = [r for r in reports if r.validator == "api_security_validator"]
        self.assertEqual([r.status for r in mine], ["not_confirmed"])

    def test_non_get_is_not_routed(self):
        ex = self._exchange(OTHER_HASH).model_copy(update={"method": "POST"})
        self.assertEqual(exposure_evidence(_finding(), ex), [])
        self.assertNotIn("api_security_validation",
                         [p.capability for p in planner.plans_for_findings(ex, [_finding()])])


class EvidenceRoutingAnalyzePathTests(_Base):
    """The analyze() route: _validate_findings with the registry's own routing."""

    def validate(self, captured_doc):
        self.server.doc = captured_doc
        orch, cfg = self._orch()
        ex = self._exchange(captured_doc)

        async def body(run):
            reports, _ = await orch._validate_findings(
                ex, [AgentReport(agent="idor", model="fake", findings=[_finding()])],
                run_context=run)
            return reports
        return self._run(orch, cfg, body)

    def test_bola_label_confirms_through_registry_routing(self):
        reports = self.validate(OTHER_HASH)
        self.assertEqual(sorted((r.validator, r.status) for r in reports),
                         [("api_security_validator", "confirmed"),
                          ("cross_identity", "not_confirmed")])

    def test_no_sensitive_field_runs_only_the_class_validator(self):
        reports = self.validate(NO_SECRET)
        self.assertEqual([r.validator for r in reports], ["cross_identity"])
        self.assertEqual(self.server.received, [])


class CaptureSweepTests(_Base):
    """A capture no agent flagged still meets the oracle via analyze()'s shape legs."""

    def analyze(self, captured_doc, live_doc=None):
        self.server.doc = captured_doc if live_doc is None else live_doc
        orch, cfg = self._orch()
        ex = self._exchange(captured_doc)

        async def body(run):
            return await orch.analyze(ex, run_context=run, bypass_cache=True)
        resp = self._run(orch, cfg, body)
        return [f for r in resp.agent_reports for f in r.findings
                if f.vulnerability_class == "excessive data exposure"]

    def test_unflagged_capture_with_another_accounts_secret_yields_a_confirmed_finding(self):
        found = self.analyze(OTHER_HASH)
        self.assertEqual(len(found), 1, found)
        self.assertTrue(found[0].confirmed)
        self.assertEqual(found[0].confirmed_by_leg, "api_security_validator")

    def test_removing_the_sweep_leg_loses_the_finding(self):
        from unittest.mock import patch
        with patch("harness.validators.api_security_validator.exposure_evidence",
                   return_value=[]):
            self.assertEqual(self.analyze(OTHER_HASH), [])

    def test_capture_without_a_secret_yields_nothing_and_sends_nothing(self):
        self.assertEqual(self.analyze(NO_SECRET), [])
        self.assertEqual(self.server.received, [])

    def test_unconfirmed_sweep_leg_is_not_kept(self):
        self.assertEqual(self.analyze(OTHER_HASH, live_doc=dict(OTHER_HASH, passwordHash="")), [])


class AccessMatrixExpectationTests(_Base):
    def _answer(self, answer, role="alice"):
        from harness import access_matrix
        access_matrix.save_answers(
            f"127.0.0.1:{self.server.server_port}",
            [{"role": role, "object_type": "Account", "action": "read", "answer": answer}],
            operator="tester")

    def validate(self):
        self.server.doc = OTHER_HASH
        orch, cfg = self._orch()
        ex = self._exchange(OTHER_HASH)

        async def body(run):
            reports, _ = await orch._validate_findings(
                ex, [AgentReport(agent="idor", model="fake", findings=[_finding()])],
                run_context=run)
            return [r for r in reports if r.validator == "api_security_validator"][0]
        return self._run(orch, cfg, body)

    def test_declared_allowed_read_stops_the_confirmation(self):
        self._answer("allowed")
        report = self.validate()
        self.assertEqual(report.status, "not_confirmed", report.summary)
        self.assertIn("access matrix declares", report.summary)

    def test_wildcard_allowed_answer_also_stops_it(self):
        self._answer("allowed", role="*")
        self.assertEqual(self.validate().status, "not_confirmed")

    def test_restrictive_or_unknown_answer_keeps_the_confirmation(self):
        for answer in ("owner_only", "unknown"):
            with self.subTest(answer=answer):
                self._answer(answer)
                self.assertEqual(self.validate().status, "confirmed")


class CompoundSecretKeyTests(_Base):
    """Compound secret-like names count on another account's object only."""

    def validate(self, doc):
        self.server.doc = doc
        orch, cfg = self._orch()
        ex = self._exchange(doc)

        async def body(run):
            reports, _ = await orch._validate_findings(
                ex, [AgentReport(agent="idor", model="fake", findings=[_finding()])],
                run_context=run)
            return [r for r in reports if r.validator == "api_security_validator"]
        return self._run(orch, cfg, body)

    def test_another_accounts_compound_token_confirms(self):
        mine = self.validate({"users": [{"username": "alice", "fooToken": "opaque-alice-value"},
                                        {"username": "bob", "fooToken": "opaque-bob-value"}]})
        self.assertEqual([r.status for r in mine], ["confirmed"])
        self.assertIn("field=$.users[1].fooToken; object=$.users[1]; owner=bob", mine[0].evidence)
        self.assertNotIn("$.users[0]", mine[0].evidence)
        self.assertNotIn("opaque-bob-value", mine[0].evidence)

    def test_callers_own_compound_token_does_not_confirm(self):
        mine = self.validate({"username": "alice", "fooToken": "opaque-alice-value"})
        self.assertEqual([r.status for r in mine], ["not_confirmed"])

    def test_csrf_and_non_secret_compound_names_never_confirm(self):
        for key, value in (("csrfToken", "opaque-csrf-value"), ("XSRF-TOKEN", "opaque-csrf-value"),
                           ("token_type", "bearer-long-value"), ("fooTokenExpires", "2026-01-01T00"),
                           ("refresh_token_length", "12345678"), ("fooToken", True),
                           ("fooToken", "ACTIVE")):
            with self.subTest(key=key):
                self.server.received.clear()
                mine = self.validate({"username": "bob", key: value})
                self.assertFalse([r for r in mine if r.confirmed], mine)

    def test_masked_compound_key_does_not_confirm(self):
        for value in ("********", None, "", "[redacted]"):
            with self.subTest(value=value):
                mine = self.validate({"username": "bob", "fooToken": value})
                self.assertFalse([r for r in mine if r.confirmed], mine)


if __name__ == "__main__":
    unittest.main()
