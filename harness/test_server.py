"""
HTTP-level tests for server.py's finding-suppression endpoints, using
FastAPI's TestClient for a real request/response cycle rather than
calling store.py functions directly (those are covered separately in
test_store.py::TestFindingSuppression). No test file previously
exercised server.py's endpoints via TestClient at all -- this is the
first one, scoped to the new suppression endpoints since those are what
this session added; it isn't a full endpoint audit of server.py.
"""
import json
import tempfile
import unittest
from pathlib import Path

import store
from models import HttpExchange, Finding


class SuppressionEndpointTests(unittest.TestCase):
    def setUp(self):
        # Isolated temp DB, same pattern as test_store.py and
        # test_report_generator.py -- never touch the real
        # harness_state.db from a test run.
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

        # Imported after the DB path is patched and inside setUp (not at
        # module level) so server.py's own module-level Orchestrator
        # construction doesn't happen until the test DB is already in
        # place, and so re-importing per test doesn't accumulate state
        # across tests via Python's module cache.
        import importlib
        import server as server_module
        importlib.reload(server_module)
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app)

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def _persist_and_get_fingerprint(self, url="https://example.com/x") -> str:
        exchange = HttpExchange(url=url, method="GET", request_headers={}, request_body="",
                                 response_status=200, response_headers={}, response_body="")
        finding = Finding(vulnerability_class="sqli", confidence=0.8, summary="s",
                           evidence="e", suggested_test="t", basis="derived")
        store.persist_findings(exchange, "test_agent", [finding])
        results = store.all_host_findings(url, include_suppressed=True)
        return results[0]["fingerprint"]

    def test_health_exposes_fail_open_telemetry(self):
        # Phase 1.4: /health surfaces the coordinator fail-open counters so the
        # historically-silent "firing all agents" state is observable.
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "ok")
        self.assertIn("coordinator_fail_opens", body)
        self.assertIn("count", body["coordinator_fail_opens"])

    def test_settings_exposes_cloud_reasoning_seam(self):
        resp = self.client.get("/settings")
        self.assertEqual(resp.status_code, 200)
        coord = resp.json().get("coordinator", {})
        self.assertIn("cloud_reasoning", coord)
        self.assertFalse(coord["cloud_reasoning"])  # default off

    def test_settings_toggles_cloud_reasoning(self):
        resp = self.client.post("/settings", json={"coordinator": {"cloud_reasoning": True}})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["coordinator"]["cloud_reasoning"])
        # GET reflects the flip.
        self.assertTrue(self.client.get("/settings").json()["coordinator"]["cloud_reasoning"])

    def test_telemetry_endpoint(self):
        resp = self.client.get("/telemetry")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("coordinator_fail_open", body)
        self.assertIn("count", body["coordinator_fail_open"])
        self.assertIn("effort_budget", body)

    def test_suppress_finding_via_post(self):
        fp = self._persist_and_get_fingerprint()
        response = self.client.post("/findings/suppress", json={"fingerprint": fp, "reason": "false positive"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["suppressed"])
        self.assertTrue(store.is_suppressed(fp))

    def test_suppressed_finding_excluded_from_subsequent_all_host_findings(self):
        fp = self._persist_and_get_fingerprint()
        self.client.post("/findings/suppress", json={"fingerprint": fp, "reason": "fp"})
        results = store.all_host_findings("https://example.com/x")
        self.assertEqual(len(results), 0)

    def test_list_suppressions_via_get(self):
        fp = self._persist_and_get_fingerprint()
        self.client.post("/findings/suppress", json={"fingerprint": fp, "reason": "noise"})
        response = self.client.get("/findings/suppressions")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["fingerprint"], fp)
        self.assertEqual(body[0]["reason"], "noise")

    def test_unsuppress_via_delete(self):
        fp = self._persist_and_get_fingerprint()
        self.client.post("/findings/suppress", json={"fingerprint": fp})
        response = self.client.delete(f"/findings/suppress/{fp}")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(store.is_suppressed(fp))

    def test_unsuppress_unknown_fingerprint_is_404(self):
        response = self.client.delete("/findings/suppress/not-a-real-fingerprint")
        self.assertEqual(response.status_code, 404)

    def test_suppress_missing_fingerprint_field_is_422(self):
        # Pydantic request validation -- confirms the endpoint actually
        # requires the field rather than silently accepting a partial body.
        response = self.client.post("/findings/suppress", json={"reason": "no fingerprint given"})
        self.assertEqual(response.status_code, 422)


class PrioritizeEndpointTests(unittest.TestCase):
    """HTTP-level coverage for POST /prioritize -- the wiring/chunking
    logic itself (surface_prioritizer.prioritize is mocked out here; its
    own batching/index-matching logic is covered by
    test_surface_prioritizer.py)."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

        import importlib
        import server as server_module
        importlib.reload(server_module)
        self.server_module = server_module
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app)

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def test_empty_items_returns_empty_results_without_calling_prioritizer(self):
        from unittest.mock import AsyncMock, patch
        with patch.object(self.server_module, "surface_prioritizer") as mock_mod:
            mock_mod.prioritize = AsyncMock()
            response = self.client.post("/prioritize", json={"items": []})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"results": []})
        mock_mod.prioritize.assert_not_called()

    def test_items_are_chunked_by_max_items_per_call(self):
        from unittest.mock import AsyncMock, patch

        self.server_module.config["surface_prioritization"] = {
            "enabled": True, "max_items_per_call": 2, "model": "m", "temperature": 0.1,
        }
        items = [{"method": "GET", "url": f"https://x.test/{i}", "param_names": []} for i in range(5)]

        async def side_effect(chunk, ollama, model, temperature):
            return [self.server_module.PrioritizeResultItem(
                method=it.method, url=it.url, ai_priority="medium", ai_score=0.5, reasoning="r",
            ) for it in chunk]

        with patch.object(self.server_module, "surface_prioritizer") as mock_mod:
            mock_mod.prioritize = AsyncMock(side_effect=side_effect)
            response = self.client.post("/prioritize", json={"items": items})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(len(body["results"]), 5)
        # 5 items, max_items_per_call=2 -> 3 chunks (2, 2, 1)
        self.assertEqual(mock_mod.prioritize.await_count, 3)

    def test_disabled_returns_403(self):
        self.server_module.config["surface_prioritization"] = {"enabled": False}
        response = self.client.post("/prioritize", json={"items": [
            {"method": "GET", "url": "https://x.test/a", "param_names": []}
        ]})
        self.assertEqual(response.status_code, 403)


class MissingAuthProbeEndpointTests(unittest.TestCase):
    """HTTP-level tests for POST /probe-missing-auth (mocked network)."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

        import importlib
        import global_throttle
        import server as server_module
        importlib.reload(server_module)
        self.server_module = server_module
        # Scope the probe to a test host; the module-level orchestrator's
        # allowed_hosts is what the endpoint hands the probe.
        server_module.orchestrator.allowed_hosts = ["t.test"]
        global_throttle.configure(0)
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app)

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def _fake(self, mapping):
        class _Resp:
            def __init__(self, status, text):
                self.status_code, self.text = status, text
                self.headers = {}

        async def fake_request(_self, method, url, headers=None, content=None):
            entry = mapping.get((method.upper(), url))
            if entry is None:
                return _Resp(404, "")
            has_auth = bool(headers) and any(k.lower() == "authorization" for k in headers)
            return _Resp(*entry.get("garbage" if has_auth else "unauth", entry["unauth"]))
        return fake_request

    def test_probes_call_shapes_and_returns_finding(self):
        from unittest.mock import patch
        m = {("GET", "http://t.test/api/report"): {"unauth": (200, '{"salary": 90000}')},
             ("GET", "http://t.test/api/tickets"): {"unauth": (401, "no")}}
        with patch("httpx.AsyncClient.request", self._fake(m)):
            resp = self.client.post("/probe-missing-auth", json={
                "base_url": "http://t.test",
                "call_shapes": [{"method": "GET", "path": "/api/report"},
                                {"method": "GET", "path": "/api/tickets"}],
                "send_garbage_token": False,
            })
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["probed"], 2)
        self.assertEqual(body["findings_count"], 1)
        self.assertEqual(body["findings"][0]["vulnerability_class"], "missing_authentication")

    def test_bare_paths_probed_as_get(self):
        from unittest.mock import patch
        m = {("GET", "http://t.test/secret"): {"unauth": (200, "leaked internal data")}}
        with patch("httpx.AsyncClient.request", self._fake(m)):
            resp = self.client.post("/probe-missing-auth", json={
                "base_url": "http://t.test", "paths": ["/secret"], "send_garbage_token": False})
        self.assertEqual(resp.json()["findings_count"], 1)

    def test_no_targets_is_400(self):
        resp = self.client.post("/probe-missing-auth", json={"base_url": "http://t.test"})
        self.assertEqual(resp.status_code, 400)


class ActiveProbeEndpointTests(unittest.TestCase):
    """POST /active-probe: guard + real F4->F2 integration (LLM loop mocked)."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

        import importlib
        import server as server_module
        importlib.reload(server_module)
        self.server_module = server_module
        server_module.orchestrator.allowed_hosts = ["shop.test"]
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app)

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    _EXCHANGE = {"url": "https://shop.test/api/report", "method": "GET",
                 "request_headers": {}, "request_body": "", "response_status": 200,
                 "response_headers": {}, "response_body": ""}

    def test_disabled_returns_403(self):
        self.server_module.orchestrator.iterative_agent_enabled = False
        resp = self.client.post("/active-probe", json={
            "exchange": self._EXCHANGE, "hypothesis": "idor on report id", "specialty": "idor"})
        self.assertEqual(resp.status_code, 403)

    def test_enabled_runs_and_integrates(self):
        from unittest.mock import patch
        import iterative_agent
        from iterative_agent import IterativeResult
        from models import Finding

        self.server_module.orchestrator.iterative_agent_enabled = True

        async def fake_run(self, exchange, hypothesis, specialty, **kw):
            r = IterativeResult(agent=f"iterative:{specialty}", stop_reason="found")
            r.handoff_note = "id=3 returned another user's record"
            r.findings = [Finding(vulnerability_class="idor", confidence=0.8, summary="idor on report",
                                  evidence="e", suggested_test="t", basis="derived", severity="high",
                                  confirmed=True)]
            return r

        with patch.object(iterative_agent.IterativeAgent, "run", fake_run):
            resp = self.client.post("/active-probe", json={
                "exchange": self._EXCHANGE, "hypothesis": "idor on report id", "specialty": "idor"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        integ = body["integration"]
        self.assertEqual(len(integ["held_findings"]), 1)
        self.assertFalse(integ["held_findings"][0]["confirmed"])  # paused, not confirmed
        self.assertTrue(integ["remembered"])
        self.assertIn("id=3", integ["grounding"])
        # remembered into host history for real
        rows = store.all_host_findings("https://shop.test/api/report")
        self.assertTrue(any(row["vulnerability_class"] == "idor" for row in rows))


class RetryAgentsEndpointTests(unittest.TestCase):
    """POST /retry-agents (F5 retry loop) + /plan-allocation, LLM/agents mocked."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"
        import importlib
        import server as server_module
        importlib.reload(server_module)
        self.server_module = server_module
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app)

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    _EXCHANGE = {"url": "https://shop.test/api/x", "method": "GET", "request_headers": {},
                 "request_body": "", "response_status": 200, "response_headers": {}, "response_body": ""}

    def test_unknown_agent_class_is_400(self):
        resp = self.client.post("/retry-agents", json={
            "exchange": self._EXCHANGE, "agent_class": "no_such_agent"})
        self.assertEqual(resp.status_code, 400)

    def test_retry_loop_stops_on_found(self):
        from unittest.mock import patch
        from effort import CallKind
        from models import AgentReport, Finding
        orch = self.server_module.orchestrator
        agent_class = next(iter(orch.agent_manager.agents))  # some real agent

        calls = {"n": 0}

        async def fake_run(names, exchange, max_body_chars=6000, prior_context="", effort_budget=None):
            calls["n"] += 1
            if effort_budget is not None:
                effort_budget.record(CallKind.AGENT_DISPATCH, "m", 500, 500)
            # produce an actionable finding on the 2nd pass
            findings = []
            if calls["n"] == 2:
                findings = [Finding(vulnerability_class="xss", confidence=0.9, summary="s",
                                    evidence="e", suggested_test="t", basis="derived")]
            return [AgentReport(agent=names[0], model="m", findings=findings)]

        with patch.object(orch.agent_manager, "run_multiple_agents", fake_run):
            resp = self.client.post("/retry-agents", json={
                "exchange": self._EXCHANGE, "agent_class": agent_class,
                "policy_overrides": {"max_retries": 5, "max_agents": 9}})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["found"])
        self.assertEqual(len(body["rounds"]), 2)  # stopped after finding on pass 2
        self.assertEqual(body["spend"]["tokens_used"], 2000)

    def test_retry_loop_respects_retry_cap(self):
        from unittest.mock import patch
        from models import AgentReport
        orch = self.server_module.orchestrator
        agent_class = next(iter(orch.agent_manager.agents))

        async def fake_run(names, exchange, max_body_chars=6000, prior_context="", effort_budget=None):
            return [AgentReport(agent=names[0], model="m", findings=[])]  # never finds

        with patch.object(orch.agent_manager, "run_multiple_agents", fake_run):
            resp = self.client.post("/retry-agents", json={
                "exchange": self._EXCHANGE, "agent_class": agent_class,
                "policy_overrides": {"max_retries": 2, "max_agents": 9}})
        body = resp.json()
        self.assertFalse(body["found"])
        self.assertEqual(len(body["rounds"]), 3)  # 1 initial + 2 retries
        self.assertIn("retry cap", body["stop_reason"])

    def test_plan_allocation_endpoint(self):
        resp = self.client.post("/plan-allocation", json={"candidates": [
            {"id": "a", "vulnerability_class": "rce", "url": "u1", "severity": "critical"},
            {"id": "b", "vulnerability_class": "xss", "url": "u2", "severity": "low"},
        ]})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("allocations", body)
        self.assertIn("guidance", body)
        # critical ranks first
        self.assertEqual(body["allocations"][0]["id"], "a")

    def test_plan_allocation_empty_is_400(self):
        resp = self.client.post("/plan-allocation", json={"candidates": []})
        self.assertEqual(resp.status_code, 400)

    def test_plan_allocation_llm_priority_reorders(self):
        from unittest.mock import AsyncMock, patch
        import allocation_prioritizer
        # LLM ranks the low-severity xss ABOVE the critical rce (app context):
        # with no budget cap all are "full", but the ORDER follows priority.
        async def fake_rank(cands, ollama, model, temperature=0.1):
            return {"a": 0.1, "b": 0.99}  # a=critical rce, b=low xss
        with patch.object(allocation_prioritizer, "rank", AsyncMock(side_effect=fake_rank)):
            resp = self.client.post("/plan-allocation", json={
                "candidates": [
                    {"id": "a", "vulnerability_class": "rce", "url": "u1", "severity": "critical"},
                    {"id": "b", "vulnerability_class": "xss", "url": "u2", "severity": "low"},
                ],
                "use_llm_priority": True})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["allocations"][0]["id"], "b")  # LLM priority won
        self.assertEqual(body["ranking"]["llm_scored"], 2)

    def test_plan_allocation_llm_failure_falls_back_to_static(self):
        from unittest.mock import AsyncMock, patch
        import allocation_prioritizer
        async def empty_rank(cands, ollama, model, temperature=0.1):
            return {}  # model failed -> no scores
        with patch.object(allocation_prioritizer, "rank", AsyncMock(side_effect=empty_rank)):
            resp = self.client.post("/plan-allocation", json={
                "candidates": [
                    {"id": "a", "vulnerability_class": "rce", "url": "u1", "severity": "critical"},
                    {"id": "b", "vulnerability_class": "xss", "url": "u2", "severity": "low"},
                ],
                "use_llm_priority": True})
        body = resp.json()
        self.assertEqual(body["allocations"][0]["id"], "a")  # static severity ranking
        self.assertEqual(body["ranking"]["llm_scored"], 0)
        self.assertEqual(body["ranking"]["static_fallback"], 2)


class SettingsValidatorToggleEndpointTests(unittest.TestCase):
    """HTTP-level coverage for the runtime validator toggles on GET/POST
    /settings -- the backend the Burp "Cross-Identity" panel drives. The
    toggles are in-memory only (never persisted), so these assert on the live
    registry state the endpoint reflects, independent of the config file's
    defaults (which a deployment may set either way)."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

        import importlib
        import server as server_module
        importlib.reload(server_module)
        self.server_module = server_module
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app)

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def test_get_settings_reports_validator_state(self):
        body = self.client.get("/settings").json()
        self.assertIn("validators", body)
        v = body["validators"]
        for key in ("enabled", "active_enabled", "cross_identity_enabled", "registered"):
            self.assertIn(key, v)

    def test_post_settings_arms_cross_identity_in_memory(self):
        resp = self.client.post("/settings", json={
            "validators": {"active_enabled": True, "cross_identity": True}})
        self.assertEqual(resp.status_code, 200)
        v = resp.json()["validators"]
        self.assertTrue(v["active_enabled"])
        self.assertTrue(v["cross_identity_enabled"])
        self.assertIn("cross_identity", v["registered"])
        # State persists within the process (a subsequent GET sees it) ...
        self.assertTrue(self.client.get("/settings").json()["validators"]["cross_identity_enabled"])
        # ... and it actually mutated the live registry the pipeline uses.
        self.assertTrue(self.server_module.orchestrator.validator_registry.cross_identity_enabled())

    def test_post_settings_disarms_cross_identity(self):
        self.client.post("/settings", json={"validators": {"cross_identity": True}})
        resp = self.client.post("/settings", json={"validators": {"cross_identity": False}})
        v = resp.json()["validators"]
        self.assertFalse(v["cross_identity_enabled"])
        self.assertNotIn("cross_identity", v["registered"])

    def test_post_settings_empty_body_is_rejected(self):
        resp = self.client.post("/settings", json={})
        self.assertEqual(resp.status_code, 400)


class InvestigateJobEndpointTests(unittest.TestCase):
    """R18: the flagship graph investigation is reachable via a tracked, cancellable
    job API (previously server.py never invoked investigate_engagement at all)."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"
        import importlib
        import server as server_module
        importlib.reload(server_module)
        self.server = server_module
        self.server.config["runs"] = {"output_dir": self._tmpdir.name,
                                       "cache_namespace": "test-isolated"}
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app)

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def _poll(self, url, want, tries=60, delay=0.05):
        import time
        last = None
        for _ in range(tries):
            last = self.client.get(url).json()
            if last.get("status") in want:
                return last
            time.sleep(delay)
        return last

    def test_start_poll_and_complete(self):
        from unittest.mock import patch, AsyncMock
        result = {"summary": {"host": "shop.test", "endpoint_count": 3}, "coverage": {"confirmed": 1}}
        with patch.object(self.server.orchestrator, "investigate_engagement",
                          new=AsyncMock(return_value=result)):
            start = self.client.post("/engagement/shop.test/investigate",
                                     json={"base_url": "http://localhost:5002", "roles": []})
            self.assertEqual(start.status_code, 200)
            job_id = start.json()["job_id"]
            self.assertTrue(job_id)
            done = self._poll(f"/engagement/shop.test/investigate/{job_id}", {"done", "error"})
        self.assertEqual(done["status"], "done", done)
        self.assertEqual(done["result"]["summary"]["endpoint_count"], 3)
        manifest = json.loads(Path(done["manifest_path"]).read_text(encoding="utf-8"))
        self.assertEqual(manifest["completion_status"], "done")
        self.assertEqual(manifest["cache_namespace"], f"test-isolated:{job_id}")
        self.assertEqual(manifest["request_count"], 0)

    def test_manifest_id_is_passed_in_an_invocation_local_context(self):
        from unittest.mock import patch
        seen = []

        async def capture(*args, **kwargs):
            ctx = kwargs["run_context"]
            seen.append((ctx.run_id, ctx.cache_namespace, ctx.config))
            return {"summary": {}}

        self.server.config["runs"]["cache_namespace"] = "job-cache"
        with patch.object(self.server.orchestrator, "investigate_engagement", new=capture):
            starts = [self.client.post(
                "/engagement/shop.test/investigate",
                json={"base_url": "http://localhost:5002"}) for _ in range(2)]
            done = [self._poll(
                f"/engagement/shop.test/investigate/{r.json()['job_id']}", {"done", "error"})
                for r in starts]

        self.assertEqual([d["status"] for d in done], ["done", "done"])
        job_ids = [r.json()["job_id"] for r in starts]
        self.assertEqual({item[0] for item in seen}, set(job_ids))
        self.assertEqual({item[1] for item in seen},
                         {f"job-cache:{job_id}" for job_id in job_ids})
        self.assertIsNot(seen[0][2], seen[1][2])
        for item, job_id in zip(seen, job_ids):
            manifest = json.loads(Path(
                self.server._INVESTIGATE_JOBS[job_id]["manifest_path"]).read_text(encoding="utf-8"))
            self.assertEqual(item[0], manifest["run_id"])

    def test_cancel_running_job(self):
        from unittest.mock import patch
        import asyncio

        async def _slow(*a, **k):
            await asyncio.sleep(30)
            return {}

        with patch.object(self.server.orchestrator, "investigate_engagement", new=_slow):
            start = self.client.post("/engagement/shop.test/investigate",
                                     json={"base_url": "http://localhost:5002"})
            job_id = start.json()["job_id"]
            cancel = self.client.post(f"/engagement/shop.test/investigate/{job_id}/cancel")
            self.assertEqual(cancel.status_code, 200)
            final = self._poll(f"/engagement/shop.test/investigate/{job_id}", {"cancelled"})
        self.assertEqual(final["status"], "cancelled", final)

    def test_status_unknown_job_404(self):
        resp = self.client.get("/engagement/shop.test/investigate/nope")
        self.assertEqual(resp.status_code, 404)

    def test_empty_base_url_rejected(self):
        resp = self.client.post("/engagement/shop.test/investigate", json={"base_url": ""})
        self.assertEqual(resp.status_code, 400)

    def test_list_jobs_for_host(self):
        from unittest.mock import patch, AsyncMock
        with patch.object(self.server.orchestrator, "investigate_engagement",
                          new=AsyncMock(return_value={"summary": {}})):
            self.client.post("/engagement/shop.test/investigate", json={"base_url": "http://localhost:5002"})
            listing = self.client.get("/engagement/shop.test/investigate")
        self.assertEqual(listing.status_code, 200)
        self.assertGreaterEqual(len(listing.json()["jobs"]), 1)


if __name__ == "__main__":
    unittest.main()
