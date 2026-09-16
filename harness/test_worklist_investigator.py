"""Tests for the Milestone-B worklist investigator: derive -> drive the iterative
agent per prioritised node -> fold findings back into the graph (no re-test).
The probe (iterative agent + network) is stubbed; the driver logic is under test."""
import asyncio
import unittest

from harness import engagement
import harness.worklist_investigator as wi
from harness.role_crawl import RoleSession


ROLES = [RoleSession("anonymous", {}),
         RoleSession("user", {"Authorization": "Bearer u"}),
         RoleSession("admin", {"Authorization": "Bearer a"})]


def _state_with(endpoints, idor_findings=None):
    st = engagement.EngagementState(host="t")
    st.ingest_role_crawl({"endpoints": endpoints, "idor_findings": idor_findings or []})
    for r in ROLES:
        st.ingest_identity(r.role, r.role, source="seed")
    return st


OBJ = {"method": "GET", "path": "/api/tickets/{id}", "by_role": {"user": 200, "admin": 200, "anonymous": 401},
       "reachable_roles": ["user", "admin"], "object_scoped": True}
ADMIN = {"method": "GET", "path": "/api/admin/users", "by_role": {"user": 200, "admin": 200, "anonymous": 401},
         "reachable_roles": ["user", "admin"], "object_scoped": False}
BENIGN = {"method": "GET", "path": "/api/health", "by_role": {"anonymous": 200, "user": 200},
          "reachable_roles": ["anonymous", "user"], "object_scoped": False}


def _found_idor():
    return {"iterative_result": {"stop_reason": "found", "findings": [
        {"vulnerability_class": "idor", "confidence": 0.8, "severity": "high", "confirmed": True,
         "summary": "IDOR", "evidence": "other id", "suggested_test": "x", "basis": "derived"}]},
        "integration": {}}


def _nothing():
    return {"iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}}


class SeedExchangeTemplateTests(unittest.TestCase):
    """R05: replay the captured request template instead of fabricating."""

    def test_replays_body_query_and_observed_object_id(self):
        node = {"method": "POST", "path": "/api/tickets/{id}",
                "template": {"method": "POST", "body": "<ticket/>", "query": "e=1",
                             "content_type": "application/xml", "object_id": "42"}}
        ex = wi._seed_exchange("http://t", node, {"Authorization": "Bearer u"}, "1")
        self.assertEqual(ex.request_body, "<ticket/>")          # real body, not empty
        self.assertIn("/api/tickets/42", ex.url)                 # observed id, not 1
        self.assertIn("e=1", ex.url)                             # query preserved, not stripped
        self.assertEqual(ex.request_headers.get("Authorization"), "Bearer u")  # probe identity
        self.assertEqual(ex.request_headers.get("Content-Type"), "application/xml")

    def test_fabricates_when_no_template(self):
        node = {"method": "GET", "path": "/api/tickets/{id}"}
        ex = wi._seed_exchange("http://t", node, {"Authorization": "Bearer u"}, "1")
        self.assertEqual(ex.request_body, "")
        self.assertIn("/api/tickets/1", ex.url)                  # falls back to id_fill
        self.assertNotIn("?", ex.url)

    def test_identity_auth_not_overwritten_by_captured_auth(self):
        # a template must NOT replay the captor's own session; only Content-Type.
        node = {"method": "POST", "path": "/api/x",
                "template": {"method": "POST", "body": "b", "query": "",
                             "content_type": "application/json", "object_id": None}}
        ex = wi._seed_exchange("http://t", node, {}, "1")   # anonymous probe
        self.assertNotIn("Authorization", ex.request_headers)
        self.assertNotIn("Cookie", ex.request_headers)


class DeriveTests(unittest.TestCase):
    def test_object_scoped_node_derives_idor(self):
        self.assertEqual(wi._derive_probe(OBJ)[0], "idor")

    def test_privileged_low_trust_node_derives_auth(self):
        st = _state_with([ADMIN])
        node = next(w for w in st.worklist(10) if w["path"] == "/api/admin/users")
        self.assertEqual(wi._derive_probe(node)[0], "auth")

    def test_benign_node_skipped(self):
        st = _state_with([BENIGN])
        node = next(w for w in st.worklist(10) if w["path"] == "/api/health")
        self.assertIsNone(wi._derive_probe(node))


class InvestigateTests(unittest.IsolatedAsyncioTestCase):
    async def test_drives_probe_and_folds_findings_back(self):
        st = _state_with([OBJ, ADMIN, BENIGN])
        calls = []
        async def probe(exchange, hypothesis, specialty, step_budget):
            calls.append({"url": exchange.url, "specialty": specialty,
                          "auth": exchange.request_headers.get("Authorization")})
            return _found_idor() if specialty == "idor" else _nothing()

        outcomes = await wi.investigate_worklist(probe, st, "http://t", ROLES, max_nodes=8)

        specialties = {c["specialty"] for c in calls}
        self.assertIn("idor", specialties)
        self.assertIn("auth", specialties)
        # benign /api/health has no actionable signal -> never probed
        self.assertNotIn("/api/health", [o["path"] for o in outcomes])
        # probed the object endpoint from the LOWEST-trust reachable role (user)
        idor_call = next(c for c in calls if c["specialty"] == "idor")
        self.assertEqual(idor_call["auth"], "Bearer u")
        self.assertIn("/api/tickets/1", idor_call["url"])   # {id} filled
        # the confirmed finding folded back -> node is now 'validated'
        ep = next(w for w in st.worklist(10) if w["path"] == "/api/tickets/{id}")
        self.assertEqual(ep["status"], "validated")

    async def test_confirm_fn_upgrades_finding_and_validates_node(self):
        st = _state_with([OBJ])
        async def probe(exchange, hypothesis, specialty, step_budget):
            # the iterative agent returns an UNCONFIRMED idor guess
            return {"iterative_result": {"stop_reason": "found", "findings": [
                {"vulnerability_class": "IDOR/BOLA", "confidence": 0.8, "severity": "high",
                 "confirmed": False, "summary": "s", "evidence": "e", "suggested_test": "t",
                 "basis": "derived"}]}, "integration": {}}
        seen = []
        async def confirm(finding, exchange):
            seen.append((finding["vulnerability_class"], exchange.url))
            finding["confirmed"] = True
            finding["confidence"] = 0.91
        out = await wi.investigate_worklist(probe, st, "http://t", ROLES, confirm_fn=confirm)
        self.assertTrue(seen)                       # confirmation ran on the finding
        self.assertTrue(out[0]["confirmed"])        # outcome reflects confirmation
        ep = next(w for w in st.worklist(10) if w["path"] == "/api/tickets/{id}")
        self.assertEqual(ep["status"], "validated")  # confirmed finding -> node validated

    async def test_validated_node_is_not_retested(self):
        st = _state_with([OBJ])
        # first pass confirms it
        await wi.investigate_worklist(lambda *a, **k: _async(_found_idor()), st, "http://t", ROLES)
        # second pass must skip the now-validated node
        second = []
        async def probe(exchange, hypothesis, specialty, step_budget):
            second.append(exchange.url)
            return _nothing()
        out = await wi.investigate_worklist(probe, st, "http://t", ROLES)
        self.assertEqual(second, [])   # nothing re-tested
        self.assertEqual(out, [])

    async def test_validated_endpoint_still_runs_preconditions_R21(self):
        # R21: a validated endpoint is not skipped wholesale -- the agent re-probe
        # for the already-confirmed class is skipped, but shape-driven precondition
        # legs (other classes) still run.
        st = _state_with([OBJ])
        await wi.investigate_worklist(lambda *a, **k: _async(_found_idor()), st, "http://t", ROLES)
        agent_calls, precond_calls = [], []
        async def probe(exchange, hypothesis, specialty, step_budget):
            agent_calls.append(specialty); return _nothing()
        async def precond(node, exchange):
            precond_calls.append(node["path"]); return []
        await wi.investigate_worklist(probe, st, "http://t", ROLES, precondition_fn=precond)
        self.assertEqual(agent_calls, [])                      # idor already confirmed -> no re-probe
        self.assertIn("/api/tickets/{id}", precond_calls)      # but preconditions still run

    async def test_precondition_budget_counts_attempts_R23(self):
        # R23: max_precondition_legs bounds ATTEMPTS, not confirmations -- a leg that
        # returns nothing still consumes the budget.
        eps = [{"method": "GET", "path": f"/api/e{i}", "by_role": {"user": 200},
                "reachable_roles": ["user"], "object_scoped": False} for i in range(10)]
        st = _state_with(eps)
        attempts = {"n": 0}
        async def precond(node, exchange):
            attempts["n"] += 1; return []                      # never confirms
        await wi.investigate_worklist(lambda *a, **k: _async(_nothing()), st, "http://t", ROLES,
                                      precondition_fn=precond, max_precondition_legs=3, max_nodes=0)
        self.assertEqual(attempts["n"], 3)                     # bounded by attempts, not confirmations

    async def test_one_node_failure_does_not_sink_the_sweep(self):
        st = _state_with([OBJ, ADMIN])
        async def probe(exchange, hypothesis, specialty, step_budget):
            if specialty == "idor":
                raise RuntimeError("probe blew up")
            return _nothing()
        out = await wi.investigate_worklist(probe, st, "http://t", ROLES)
        self.assertEqual(len(out), 2)
        self.assertTrue(any("error" in o for o in out))


class PreconditionTests(unittest.IsolatedAsyncioTestCase):
    """Proactive, shape-driven legs run REGARDLESS of agent findings (the fix for
    the detection->confirmation coupling). The precondition_fn is stubbed here to
    return already-confirmed findings; the wiring in investigate_worklist is under
    test, not the orchestrator's shape logic."""

    async def test_precondition_confirms_node_with_no_agent_hypothesis(self):
        # A benign node the agent probe would SKIP (derive -> None) still gets a
        # proactive leg run, and a confirmed finding folds back and validates it.
        st = _state_with([BENIGN])
        agent_calls = []
        async def probe(exchange, hypothesis, specialty, step_budget):
            agent_calls.append(exchange.url)
            return _nothing()
        async def precondition(node, exchange):
            return [{"vulnerability_class": "jwt", "confidence": 0.9, "severity": "high",
                     "confirmed": True, "summary": "forged alg:none accepted",
                     "evidence": "e", "basis": "derived"}]
        out = await wi.investigate_worklist(
            probe, st, "http://t", ROLES, precondition_fn=precondition)
        self.assertEqual(agent_calls, [])                 # agent never ran on the benign node
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0]["confirmed"])
        self.assertEqual(out[0]["precondition_findings"], 1)
        ep = next(w for w in st.worklist(10) if w["path"] == "/api/health")
        self.assertEqual(ep["status"], "validated")        # proactive confirm sinks the node

    async def test_precondition_and_agent_both_fold_in(self):
        st = _state_with([OBJ])
        async def probe(exchange, hypothesis, specialty, step_budget):
            return _found_idor()
        async def precondition(node, exchange):
            return [{"vulnerability_class": "jwt", "confidence": 0.9, "severity": "high",
                     "confirmed": True, "summary": "jwt forged", "evidence": "e", "basis": "derived"}]
        out = await wi.investigate_worklist(
            probe, st, "http://t", ROLES, precondition_fn=precondition)
        classes = {f["vulnerability_class"] for f in out[0]["findings_detail"]}
        self.assertIn("jwt", classes)     # proactive leg
        self.assertIn("idor", classes)    # agent finding

    async def test_precondition_returning_nothing_records_no_outcome(self):
        # A shape-scan that confirms nothing on a benign node must not flood the
        # outcome list with empty entries.
        st = _state_with([BENIGN])
        async def precondition(node, exchange):
            return []
        out = await wi.investigate_worklist(
            lambda *a, **k: _async(_nothing()), st, "http://t", ROLES, precondition_fn=precondition)
        self.assertEqual(out, [])

    async def test_precondition_failure_does_not_sink_sweep(self):
        st = _state_with([OBJ])
        async def precondition(node, exchange):
            raise RuntimeError("leg blew up")
        async def probe(exchange, hypothesis, specialty, step_budget):
            return _found_idor()
        out = await wi.investigate_worklist(
            probe, st, "http://t", ROLES, precondition_fn=precondition)
        self.assertEqual(len(out), 1)          # agent probe still recorded
        self.assertTrue(out[0]["confirmed"])

    async def test_precondition_findings_survive_agent_probe_error(self):
        st = _state_with([OBJ])
        async def precondition(node, exchange):
            return [{"vulnerability_class": "jwt", "confidence": 0.9, "severity": "high",
                     "confirmed": True, "summary": "jwt forged", "evidence": "e", "basis": "derived"}]
        async def probe(exchange, hypothesis, specialty, step_budget):
            raise RuntimeError("agent blew up")
        out = await wi.investigate_worklist(
            probe, st, "http://t", ROLES, precondition_fn=precondition)
        self.assertEqual(len(out), 1)
        self.assertIn("error", out[0])
        # the proactively-confirmed finding is not lost when the agent errors
        self.assertEqual(out[0]["precondition_findings"], 1)
        self.assertEqual(len(out[0]["findings_detail"]), 1)

    async def test_precondition_leg_cap_is_respected(self):
        colls = ["tickets", "orders", "reports", "invoices", "docs"]
        eps = [dict(OBJ, path=f"/api/{c}/{{id}}") for c in colls]
        st = _state_with(eps)
        ran = []
        async def precondition(node, exchange):
            ran.append(node["path"])
            return [{"vulnerability_class": "jwt", "confidence": 0.9, "severity": "high",
                     "confirmed": True, "summary": "s", "evidence": "e", "basis": "derived"}]
        await wi.investigate_worklist(
            lambda *a, **k: _async(_nothing()), st, "http://t", ROLES,
            precondition_fn=precondition, max_nodes=0, max_precondition_legs=2)
        self.assertEqual(len(ran), 2)   # stops after the cap of confirmed proactive legs


def _async(value):
    async def _c(*a, **k):
        return value
    return _c()


if __name__ == "__main__":
    unittest.main()
