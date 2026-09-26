"""Tests for the engagement driver (slice 4): plan + toggle-gated execute."""
import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import store
from harness import engagement
from harness.engagement import EngagementState


def _seed_state(host="shop.test"):
    st = EngagementState(host=host)
    # a privileged, anonymous-reachable endpoint (should rank high) + a plain one
    st.ingest_role_crawl({"endpoints": [
        {"method": "GET", "path": "/rest/admin/config", "by_role": {"anonymous": 200},
         "reachable_roles": ["anonymous"], "object_scoped": False},
        {"method": "GET", "path": "/api/public", "by_role": {"anonymous": 200},
         "reachable_roles": ["anonymous"], "object_scoped": False}]})
    return st


class DriverPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import harness.server as server_module
        cls.orch = server_module.orchestrator

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.orig = store._DB_PATH
        store._DB_PATH = Path(self.tmp.name) / "t.db"

    def tearDown(self):
        store._DB_PATH = self.orig
        self.tmp.cleanup()

    def test_plan_empty_state(self):
        r = asyncio.run(self.orch.plan_engagement("nohost.test"))
        self.assertEqual(r["targets"], [])
        self.assertFalse(r["executed"])

    def test_plan_ranks_and_allocates(self):
        store.save_engagement("shop.test", _seed_state().to_dict())
        r = asyncio.run(self.orch.plan_engagement("shop.test", base_url="http://shop.test/"))
        self.assertFalse(r["executed"])
        self.assertTrue(r["targets"])
        # privileged anon-reachable endpoint ranks first
        self.assertEqual(r["targets"][0]["path"], "/rest/admin/config")
        # each target carries a governor action
        self.assertIn(r["targets"][0]["action"], ("full", "reduced", "deferred"))

    def test_validated_excluded_from_plan(self):
        st = _seed_state()
        st.ingest_findings("http://shop.test/rest/admin/config", "GET",
                           [{"vulnerability_class": "misconfig", "severity": "high",
                             "confidence": 0.9, "confirmed": True, "confirmed_by_leg": "sqlmap"}])
        store.save_engagement("shop.test", st.to_dict())
        r = asyncio.run(self.orch.plan_engagement("shop.test", base_url="http://shop.test/"))
        paths = {t["path"] for t in r["targets"]}
        self.assertNotIn("/rest/admin/config", paths)  # validated -> not "test next"

    def test_run_without_execute_is_plan(self):
        store.save_engagement("shop.test", _seed_state().to_dict())
        r = asyncio.run(self.orch.run_engagement("shop.test", "http://shop.test/", execute=False))
        self.assertFalse(r["executed"])
        self.assertIn("plan only", r.get("note", ""))

    def test_execute_refused_when_config_off(self):
        store.save_engagement("shop.test", _seed_state().to_dict())
        self.orch.engagement_driver_execute = False
        r = asyncio.run(self.orch.run_engagement("shop.test", "http://shop.test/", execute=True))
        self.assertFalse(r["executed"])
        self.assertIn("refused", r.get("note", ""))

    def test_replanning_loop_bounded_and_dedups(self):
        # The loop should not re-fetch the same target across rounds; with a
        # single funded endpoint it converges after one productive round.
        from harness import global_throttle
        global_throttle.configure(0)
        store.save_engagement("shop.test", _seed_state().to_dict())
        self.orch.allowed_hosts = ["shop.test"]
        self.orch.engagement_driver_execute = True
        fetched = []

        class _Resp:
            status_code = 200; headers = {}; text = "{}"

        async def fake_request(self, method, url, **kw):  # W-16: transport uses .request
            fetched.append(url)
            return _Resp()

        async def fake_analyze(exchange, *a, **k):
            from harness.models import AnalysisResponse
            return AnalysisResponse(coordinator_model="m", dispatched_agents=[], agent_reports=[],
                                    summary="", test_plans=[])
        try:
            with patch("httpx.AsyncClient.request", fake_request), \
                 patch.object(self.orch, "analyze", fake_analyze):
                r = asyncio.run(self.orch.run_engagement(
                    "shop.test", "http://shop.test/", max_targets=5, max_rounds=3, execute=True))
            # no URL fetched twice despite multiple rounds
            self.assertEqual(len(fetched), len(set(fetched)))
        finally:
            self.orch.engagement_driver_execute = False

    def test_execute_runs_when_enabled(self):
        from harness import global_throttle
        global_throttle.configure(0)
        store.save_engagement("shop.test", _seed_state().to_dict())
        self.orch.allowed_hosts = ["shop.test"]
        self.orch.engagement_driver_execute = True

        class _Resp:
            status_code = 200
            headers = {}
            text = '{"data":1}'

        async def fake_request(self, method, url, **kw):  # W-16: transport uses .request
            return _Resp()

        # analyze is heavy (real agents) -- stub it; we're testing the driver loop.
        async def fake_analyze(exchange, *a, **k):
            from harness.models import AnalysisResponse
            return AnalysisResponse(coordinator_model="m", dispatched_agents=[], agent_reports=[],
                                    summary="", test_plans=[])
        try:
            with patch("httpx.AsyncClient.request", fake_request), \
                 patch.object(self.orch, "analyze", fake_analyze):
                r = asyncio.run(self.orch.run_engagement(
                    "shop.test", "http://shop.test/", max_targets=3, max_rounds=2, execute=True))
            self.assertTrue(r["executed"])
            self.assertTrue(r["rounds"])                       # the re-planning loop ran
            self.assertTrue(any(rd.get("targets_run", 0) > 0 for rd in r["rounds"]))
        finally:
            self.orch.engagement_driver_execute = False


class DriverEndpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.orig = store._DB_PATH
        store._DB_PATH = Path(self.tmp.name) / "t.db"
        import harness.server as server_module
        self.server_module = server_module
        from fastapi.testclient import TestClient
        # RB-1: state-changing routes require the bearer token even from
        # loopback; attach the (ephemeral, in this test env) token.
        self.client = TestClient(server_module.app, base_url="http://localhost",
                                 headers={"Authorization": f"Bearer {server_module._mutation_token()}"})

    def tearDown(self):
        store._DB_PATH = self.orig
        self.tmp.cleanup()

    def test_run_endpoint_plan(self):
        store.save_engagement("shop.test", _seed_state().to_dict())
        resp = self.client.post("/engagement/shop.test/run",
                                json={"base_url": "http://shop.test/", "max_targets": 5})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertFalse(body["executed"])
        self.assertTrue(body["targets"])

    def test_execute_requires_base_url(self):
        resp = self.client.post("/engagement/shop.test/run", json={"execute": True})
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
