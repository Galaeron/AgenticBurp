"""Tests for the 2026-11-03 Juice Shop yield fixes: planner plans are bound,
dispatched or explained (plan_dispatch + store), iterative candidates are
reviewed and their prose-named injection classes planned (pivot_memory), a
reflected query parameter becomes an XSS hypothesis, and the worklist spends its
precondition budget only on nodes that warrant a leg. Validators and probes are
stubbed; no network."""
import asyncio
import tempfile
import unittest
from dataclasses import dataclass, field
from pathlib import Path

from harness import engagement, pivot_memory, plan_dispatch, planner, store
import harness.worklist_investigator as wi
from harness.models import AgentReport, Finding, HttpExchange, TestPlan, ValidationReport
from harness.orchestrator_helpers import reflected_parameter_findings
from harness.role_crawl import RoleSession

URL = "https://shop.test/rest/user/login"


def _exchange(url=URL, method="POST", body='{"email":"a@b.test","password":"x"}',
              response_body=""):
    return HttpExchange(url=url, method=method,
                        request_headers={"Content-Type": "application/json"},
                        request_body=body, response_status=200, response_headers={},
                        response_body=response_body)


def _finding(vc="xss", summary="s", conf=0.6, severity="high", **kw):
    return Finding(vulnerability_class=vc, confidence=conf, summary=summary, evidence="e",
                   suggested_test="t", basis="derived", severity=severity, **kw)


def _plan(pid, capability, finding_class, severity="high", confidence=0.6):
    return TestPlan(id=pid, capability=capability, finding_class=finding_class,
                    category=finding_class, source_exchange_url=URL,
                    severity=severity, confidence=confidence)


class _TempDb(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._orig = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "t.db"

    def tearDown(self):
        store._DB_PATH = self._orig
        self._tmpdir.cleanup()

    def _status(self, pid):
        return store.get_test_plan(pid)["status"]


class StoreDispatchTests(_TempDb):
    def test_bind_records_result_once(self):
        store.persist_test_plans(_exchange(), [_plan("p1", "reflection_context_validation", "xss")])
        ok, _ = store.record_plan_dispatch("p1", status="not_confirmed", validator="browser_xss")
        self.assertTrue(ok)
        self.assertEqual(self._status("p1"), "not_confirmed")
        # a plan that already has a result is never overwritten
        ok, reason = store.record_plan_dispatch("p1", status="confirmed", validator="x",
                                                confirmed=True)
        self.assertFalse(ok)
        self.assertEqual(reason, "plan already has a result")
        self.assertFalse(store.mark_plan_not_dispatchable("p1", "late"))
        self.assertEqual(self._status("p1"), "not_confirmed")

    def test_not_dispatchable_keeps_reason(self):
        store.persist_test_plans(_exchange(), [_plan("p2", "jwt_validation", "jwt")])
        self.assertTrue(store.mark_plan_not_dispatchable("p2", "active validation is off"))
        notes = {n["plan_id"]: n for n in store.plan_dispatch_notes("shop.test")}
        self.assertEqual(notes["p2"]["status"], "not_dispatchable")
        self.assertIn("active validation is off", notes["p2"]["dispatch_note"])


@dataclass
class _Validator:
    name: str
    active: bool = True


class _Registry:
    def __init__(self, names, active_enabled=True):
        self.validators = {n: _Validator(n) for n in names}
        self.enabled = True
        self.active_enabled = active_enabled


class _FakeOrch:
    """Records each _validate_findings call; answers with a fixed report per
    validator name it is allowed to run."""

    def __init__(self, answers, registry_names=None, active_enabled=True):
        self.config = {}
        self.answers = answers
        self.validator_registry = _Registry(registry_names or list(answers), active_enabled)
        self.calls = []

    async def _validate_findings(self, exchange, reports, *, run_context=None,
                                 only_validators=None):
        self.calls.append((only_validators, [f.vulnerability_class for r in reports
                                             for f in r.findings]))
        out = []
        for name in sorted(only_validators or ()):
            if name in self.answers:
                cls = reports[0].findings[0].vulnerability_class
                out.append(ValidationReport(validator=name, status=self.answers[name],
                                            finding_class=cls))
        return out, []


class DispatchPlansTests(_TempDb):
    def _run(self, orch, plans, findings, vreports=None, **kw):
        store.persist_test_plans(_exchange(), plans)
        reports = [AgentReport(agent="iterative:auth", model="m", findings=findings)]
        return asyncio.run(plan_dispatch.dispatch_plans(
            orch, _exchange(), plans, reports, vreports if vreports is not None else [], **kw))

    def test_existing_result_is_bound_without_sending(self):
        orch = _FakeOrch({"browser_xss": "not_confirmed"})
        vr = [ValidationReport(validator="browser_xss", status="not_confirmed", finding_class="xss")]
        out = self._run(orch, [_plan("x1", "reflection_context_validation", "xss")],
                        [_finding("xss")], vr)
        self.assertEqual(out["bound"], ["x1"])
        self.assertEqual(orch.calls, [])
        self.assertEqual(self._status("x1"), "not_confirmed")

    def test_unrun_plan_is_dispatched_to_its_validator_only(self):
        orch = _FakeOrch({"jwt_forge": "not_confirmed"})
        out = self._run(orch, [_plan("j1", "jwt_validation", "jwt")], [_finding("jwt")])
        self.assertEqual(out["dispatched"], ["j1"])
        self.assertEqual(orch.calls, [(frozenset({"jwt_forge"}), ["jwt"])])
        self.assertEqual(self._status("j1"), "not_confirmed")

    def test_validated_pass_explains_and_never_resends(self):
        orch = _FakeOrch({"jwt_forge": "not_confirmed"}, active_enabled=False)
        out = self._run(orch, [_plan("j2", "jwt_validation", "jwt")], [_finding("jwt")],
                        validated=True)
        self.assertEqual(out["not_dispatchable"], ["j2"])
        self.assertEqual(orch.calls, [])
        note = store.plan_dispatch_notes("shop.test")[0]["dispatch_note"]
        self.assertIn("active validation is off", note)

    def test_capability_without_local_validator_is_explained(self):
        orch = _FakeOrch({})
        out = self._run(orch, [_plan("b1", "business_logic_review", "business_logic")],
                        [_finding("business_logic")])
        self.assertEqual(out["not_dispatchable"], ["b1"])
        self.assertEqual(orch.calls, [])

    def test_cap_dispatches_highest_priority_first_and_defers_the_rest(self):
        orch = _FakeOrch({"jwt_forge": "not_confirmed", "csrf": "not_confirmed"})
        plans = [_plan("low", "csrf_validation", "csrf", severity="low"),
                 _plan("high", "jwt_validation", "jwt", severity="critical")]
        out = self._run(orch, plans, [_finding("csrf"), _finding("jwt")], max_dispatch=1)
        self.assertEqual(out["dispatched"], ["high"])
        self.assertEqual(out["deferred"], ["low"])
        self.assertEqual(self._status("low"), "proposed")   # budget, not inability

    def test_spent_run_budget_defers(self):
        class _Budget:
            remaining = 0
        class _Ctx:
            budget = _Budget()
        orch = _FakeOrch({"jwt_forge": "not_confirmed"})
        out = self._run(orch, [_plan("j3", "jwt_validation", "jwt")], [_finding("jwt")],
                        run_context=_Ctx())
        self.assertEqual(out["deferred"], ["j3"])
        self.assertEqual(orch.calls, [])

    def test_priority_order(self):
        plans = [_plan("a", "csrf_validation", "csrf", severity="medium", confidence=0.9),
                 _plan("b", "jwt_validation", "jwt", severity="high", confidence=0.2),
                 _plan("c", "nosql_validation", "nosql", severity="high", confidence=0.8)]
        self.assertEqual([p.id for p in plan_dispatch.prioritize(plans)], ["c", "b", "a"])

    def test_dispatch_limit_reads_optional_config(self):
        self.assertEqual(plan_dispatch.dispatch_limit({}), plan_dispatch.DEFAULT_MAX_DISPATCH)
        self.assertEqual(plan_dispatch.dispatch_limit({"validators": {"plan_dispatch_max": 2}}), 2)
        self.assertEqual(plan_dispatch.dispatch_limit({"validators": {"plan_dispatch_max": True}}),
                         plan_dispatch.DEFAULT_MAX_DISPATCH)


class InjectionFollowupTests(unittest.TestCase):
    def test_prose_sql_injection_on_login_plans_each_body_parameter(self):
        f = _finding("Authentication Bypass / SQL Injection", summary="login may be injectable")
        follow = plan_dispatch.injection_followups([f], _exchange())
        self.assertEqual({x.vulnerability_class for x in follow}, {"sqli"})
        self.assertEqual({x.parameter_name for x in follow}, {"email", "password"})
        self.assertTrue(all(x.confidence <= 0.35 and x.basis == "derived" for x in follow))
        caps = {p.capability for p in planner.plans_for_findings(_exchange(), [f] + follow)}
        self.assertIn("sql_injection_validation", caps)

    def test_finding_already_of_that_class_gets_no_followup(self):
        self.assertEqual(plan_dispatch.injection_followups(
            [_finding("sqli", summary="SQL injection in email")], _exchange()), [])

    def test_nosql_is_not_read_as_sql(self):
        f = _finding("auth bypass", summary="NoSQL injection via operator in password")
        self.assertEqual(plan_dispatch.injection_classes(f), ["nosql"])

    def test_no_named_class_gets_nothing(self):
        self.assertEqual(plan_dispatch.injection_followups(
            [_finding("auth bypass", summary="weak lockout")], _exchange()), [])


@dataclass
class _FakeResult:
    agent: str = "iterative:auth"
    findings: list = field(default_factory=list)
    handoff_note: str = ""
    stop_reason: str = "found"


class PivotReviewHookTests(_TempDb):
    def test_review_sees_persisted_plans_before_findings_are_remembered(self):
        seen = {}

        async def review(findings, plans):
            seen["plans_in_store"] = all(store.get_test_plan(p.id) for p in plans)
            seen["findings_in_store"] = len(store.all_host_findings(URL))
            seen["classes"] = {f.vulnerability_class for f in findings}
            for f in findings:
                f.case_id = "case-1"

        r = _FakeResult(findings=[_finding("Authentication Bypass / SQL Injection")])
        out = asyncio.run(pivot_memory.integrate(r, _exchange(), review=review))
        self.assertTrue(seen["plans_in_store"])
        self.assertEqual(seen["findings_in_store"], 0)
        self.assertIn("sqli", seen["classes"])
        self.assertTrue(out.remembered)
        self.assertTrue(store.all_host_findings(URL))

    def test_failing_review_still_remembers(self):
        async def review(findings, plans):
            raise RuntimeError("validator blew up")
        r = _FakeResult(findings=[_finding("xss")])
        out = asyncio.run(pivot_memory.integrate(r, _exchange(), review=review))
        self.assertTrue(out.remembered)
        self.assertTrue(store.all_host_findings(URL))

    def test_dry_run_never_reviews(self):
        called = []

        async def review(findings, plans):
            called.append(1)
        r = _FakeResult(findings=[_finding("xss")])
        asyncio.run(pivot_memory.integrate(r, _exchange(), persist=False, review=review))
        self.assertEqual(called, [])


class ReflectedParameterTests(unittest.TestCase):
    def _get(self, url, body):
        return HttpExchange(url=url, method="GET", request_headers={}, request_body="",
                            response_status=200, response_headers={}, response_body=body)

    def test_reflected_query_value_becomes_xss_plan(self):
        ex = self._get("https://shop.test/search?q=orangejuice&page=1",
                       "<p>Results for orangejuice</p>")
        found = reflected_parameter_findings(ex)
        self.assertEqual([(f.vulnerability_class, f.parameter_name) for f in found],
                         [("xss", "q")])
        caps = {p.capability for p in planner.plans_for_findings(ex, found)}
        self.assertIn("reflection_context_validation", caps)

    def test_short_or_absent_values_are_not_reflections(self):
        self.assertEqual(reflected_parameter_findings(
            self._get("https://shop.test/search?q=ab", "ab ab")), [])
        self.assertEqual(reflected_parameter_findings(
            self._get("https://shop.test/search?q=orangejuice", "<p>nothing</p>")), [])
        self.assertEqual(reflected_parameter_findings(
            self._get("https://shop.test/search?q=orangejuice", "")), [])


ROLES = [RoleSession("anonymous", {}), RoleSession("user", {"Authorization": "Bearer u"})]


def _state_with(endpoints):
    st = engagement.EngagementState(host="t")
    st.ingest_role_crawl({"endpoints": endpoints, "idor_findings": []})
    for r in ROLES:
        st.ingest_identity(r.role, r.role, source="seed")
    return st


def _benign(i):
    return {"method": "GET", "path": f"/api/page{i}", "by_role": {"anonymous": 200},
            "reachable_roles": ["anonymous"], "object_scoped": False}


async def _nothing(*a, **k):
    return {"iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}}


class WorklistPreconditionBudgetTests(unittest.IsolatedAsyncioTestCase):
    async def test_unwarranted_nodes_do_not_spend_the_budget(self):
        st = _state_with([_benign(i) for i in range(5)])
        ran = []

        async def precondition(node, exchange):
            ran.append(node["path"])
            return []
        precondition.warranted = lambda node, exchange: node["path"] in ("/api/page3", "/api/page4")
        summary = {}
        await wi.investigate_worklist(_nothing, st, "http://t", ROLES, precondition_fn=precondition,
                                      max_nodes=0, max_precondition_legs=2, summary_out=summary)
        # before the fix the first two (unwarranted) nodes used both legs
        self.assertEqual(sorted(ran), ["/api/page3", "/api/page4"])
        self.assertNotIn("budget_exhausted", summary["skipped_by_reason"])

    async def test_warranted_node_past_the_budget_is_budget_exhausted(self):
        st = _state_with([_benign(i) for i in range(3)])

        async def precondition(node, exchange):
            return []
        precondition.warranted = lambda node, exchange: True
        summary = {}
        await wi.investigate_worklist(_nothing, st, "http://t", ROLES, precondition_fn=precondition,
                                      max_nodes=0, max_precondition_legs=1, summary_out=summary)
        self.assertEqual(summary["skipped_by_reason"].get("budget_exhausted"), 2)

    async def test_function_without_warranted_keeps_old_accounting(self):
        st = _state_with([_benign(i) for i in range(3)])
        ran = []

        async def precondition(node, exchange):
            ran.append(node["path"])
            return []
        await wi.investigate_worklist(_nothing, st, "http://t", ROLES, precondition_fn=precondition,
                                      max_nodes=0, max_precondition_legs=1)
        self.assertEqual(len(ran), 1)


class WriteEndpointTemplateTests(unittest.TestCase):
    def _probe_variant(self, body='{"email":"probe@example.test"}'):
        return {"source": engagement.ACCESS_MATRIX_SOURCE,
                "template": {"method": "POST", "body": body, "query": "",
                             "content_type": "application/json"}}

    def test_write_node_takes_its_probe_shape_and_gets_a_probe(self):
        node = {"method": "POST", "path": "/rest/user/login", "reachable_roles": [],
                "capture_variants": [self._probe_variant()]}
        node = wi._with_probe_template(node)
        self.assertEqual(node["template"]["body"], '{"email":"probe@example.test"}')
        self.assertEqual(node["template_source"], engagement.ACCESS_MATRIX_SOURCE)
        specialty, hypothesis = wi._derive_probe(node)
        self.assertEqual(specialty, "injection")
        self.assertIn("body parameters", hypothesis)

    def test_reads_and_empty_bodies_are_left_alone(self):
        get = {"method": "GET", "path": "/api/x", "capture_variants": [self._probe_variant()]}
        self.assertNotIn("template", wi._with_probe_template(get))
        empty = {"method": "POST", "path": "/api/x", "capture_variants": [self._probe_variant("")]}
        self.assertNotIn("template", wi._with_probe_template(empty))
        self.assertIsNone(wi._derive_probe({"method": "POST", "path": "/api/x"}))

    def test_captured_template_wins(self):
        node = {"method": "POST", "path": "/api/x", "template": {"body": "a=1"},
                "capture_variants": [self._probe_variant()]}
        self.assertEqual(wi._with_probe_template(node)["template"], {"body": "a=1"})


if __name__ == "__main__":
    unittest.main()
