"""W-11: swallowed-exception + diagnostics observability.

Makes the "why did this target produce zero/few findings?" question answerable
from /telemetry rather than server logs: a swallowed exception increments a
visible counter, and the snapshot composes the fail-open / scope-denial /
crashed-validator signals in one place.
"""
import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import yaml

from harness import store
from harness import telemetry
from harness.orchestrator import Orchestrator
from harness.models import AgentReport, Finding, HttpExchange

_HARNESS = Path(__file__).resolve().parent


class TelemetryUnitTests(unittest.TestCase):
    def setUp(self):
        telemetry.reset()

    def tearDown(self):
        telemetry.reset()

    def test_record_swallowed_exception_counts_by_site_and_type(self):
        telemetry.record_swallowed_exception("site_a", ValueError("x"))
        telemetry.record_swallowed_exception("site_a", ValueError("y"))
        telemetry.record_swallowed_exception("site_b", KeyError("z"))
        self.assertEqual(telemetry.total_swallowed(), 3)
        sw = telemetry.swallowed_exceptions()
        self.assertEqual(sw["site_a:ValueError"], 2)
        self.assertEqual(sw["site_b:KeyError"], 1)

    def test_record_event_counts(self):
        telemetry.record_event("scope_denied")
        telemetry.record_event("scope_denied", 2)
        self.assertEqual(telemetry.events()["scope_denied"], 3)

    def test_snapshot_shape(self):
        telemetry.record_swallowed_exception("v", RuntimeError())
        telemetry.record_event("scope_denied")
        snap = telemetry.snapshot()
        self.assertEqual(snap["swallowed_exceptions"]["total"], 1)
        self.assertIn("v:RuntimeError", snap["swallowed_exceptions"]["by_site"])
        self.assertEqual(snap["events"]["scope_denied"], 1)
        self.assertIn("coordinator_fail_open", snap)

    def test_recording_never_raises(self):
        telemetry.record_swallowed_exception("site", None)
        telemetry.record_event("x")


class TelemetryWiringTests(unittest.TestCase):
    """A validator that throws during dispatch increments the visible counter --
    the exact 'a leg crashes on every exchange so nothing confirms' case."""

    def setUp(self):
        telemetry.reset()
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = store._DB_PATH
        store._DB_PATH = Path(self._tmp.name) / "state.db"

    def tearDown(self):
        store._DB_PATH = self._orig
        self._tmp.cleanup()
        telemetry.reset()

    def _config(self):
        with open(_HARNESS / "config.yaml") as f:
            cfg = yaml.safe_load(f) or {}
        cfg.setdefault("validators", {})["active_enabled"] = False
        cfg.setdefault("critique", {})["enabled"] = False
        cfg.setdefault("autonomous_discovery", {})["enabled"] = False
        cfg.setdefault("server", {})["allowed_hosts"] = ["target.test"]
        return cfg

    def test_crashed_validator_increments_counter(self):
        orch = Orchestrator(self._config())

        class _Boom:
            name = "boom"
            active = False
            def applies(self, f, e):
                return True
            def plan(self, f, e):
                return None
            async def validate(self, f, e):
                raise RuntimeError("kaboom")

        orch.validator_registry.for_finding = MagicMock(return_value=[_Boom()])
        orch.validator_registry.bind_run_context = MagicMock(side_effect=lambda vs, rc: vs)
        exchange = HttpExchange(url="http://target.test/x", method="GET")
        finding = Finding(vulnerability_class="sqli", confidence=0.5, summary="s",
                          evidence="e", suggested_test="t", basis="derived")
        asyncio.run(orch._validate_findings(exchange, [AgentReport(agent="a", model="m", findings=[finding])]))

        sw = telemetry.swallowed_exceptions()
        self.assertGreaterEqual(sw.get("validator_dispatch.boom:RuntimeError", 0), 1)
        self.assertGreaterEqual(telemetry.total_swallowed(), 1)


class TelemetryInvocationBindingTests(unittest.TestCase):
    """W-11: two overlapping run contexts must not contaminate each other's
    saved explanation, and each snapshot must contain only its own run's
    events when scoped by run_id."""

    def setUp(self):
        telemetry.reset()

    def tearDown(self):
        telemetry.reset()

    def test_concurrent_runs_record_distinct_events(self):
        async def run_a():
            telemetry.bind_current_run("run-a")
            telemetry.record_event("scope_denied")
            await asyncio.sleep(0.02)
            telemetry.record_swallowed_exception("site_a", ValueError())

        async def run_b():
            telemetry.bind_current_run("run-b")
            telemetry.record_swallowed_exception("site_b", KeyError())
            await asyncio.sleep(0.01)
            telemetry.record_event("scope_denied", 3)

        async def run_both():
            await asyncio.gather(run_a(), run_b())

        asyncio.run(run_both())

        snap_a = telemetry.snapshot("run-a")
        snap_b = telemetry.snapshot("run-b")
        self.assertEqual(snap_a["scope"], "run")
        self.assertEqual(snap_a["run_id"], "run-a")
        self.assertEqual(snap_a["events"].get("scope_denied"), 1)
        self.assertEqual(snap_a["swallowed_exceptions"]["total"], 1)
        self.assertIn("site_a:ValueError", snap_a["swallowed_exceptions"]["by_site"])
        self.assertNotIn("site_b:KeyError", snap_a["swallowed_exceptions"]["by_site"])

        self.assertEqual(snap_b["events"].get("scope_denied"), 3)
        self.assertEqual(snap_b["swallowed_exceptions"]["total"], 1)
        self.assertIn("site_b:KeyError", snap_b["swallowed_exceptions"]["by_site"])
        self.assertNotIn("site_a:ValueError", snap_b["swallowed_exceptions"]["by_site"])

    def test_unscoped_snapshot_declares_process_scope_and_run_count(self):
        telemetry.bind_current_run("run-a")
        telemetry.record_event("x")
        telemetry.bind_current_run("run-b")
        telemetry.record_event("y")
        snap = telemetry.snapshot()
        self.assertEqual(snap["scope"], "process")
        self.assertEqual(snap["runs_observed"], 2)
        self.assertIn("note", snap)

    def test_reset_one_run_leaves_the_other_intact(self):
        telemetry.bind_current_run("run-a")
        telemetry.record_event("x")
        telemetry.bind_current_run("run-b")
        telemetry.record_event("y")
        telemetry.reset("run-a")
        self.assertEqual(telemetry.events("run-a"), {})
        self.assertEqual(telemetry.events("run-b").get("y"), 1)

    def test_two_overlapping_analyze_calls_bind_distinct_run_ids(self):
        """The real production caller: two top-level Orchestrator.analyze()
        invocations overlapping must each bind their own run_context.run_id,
        not a shared/global value."""
        import yaml
        cfg = yaml.safe_load((_HARNESS / "config.yaml").read_text(encoding="utf-8")) or {}
        cfg.setdefault("validators", {})["active_enabled"] = False
        cfg.setdefault("critique", {})["enabled"] = False
        cfg.setdefault("autonomous_discovery", {})["enabled"] = False
        cfg.setdefault("iterative_agent", {})["enabled"] = False
        cfg.setdefault("engagement", {})["auto_escalate"] = False
        cfg.setdefault("server", {})["allowed_hosts"] = ["one.test", "two.test"]

        import shutil
        import harness.cache as cache
        tmp = tempfile.mkdtemp(prefix="telemetry_binding_")
        orig_db, orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(tmp) / "state.db"
        cache.init_cache(db_path=str(Path(tmp) / "cache.db"))
        try:
            orch = Orchestrator(cfg)
            agent_names = list(orch.agent_manager.agents)[:1]
            observed_run_ids = []

            async def inert_agent(name, exchange, max_body_chars, prior_context):
                observed_run_ids.append(telemetry.current_run_id())
                telemetry.record_event("dispatched")
                await asyncio.sleep(0.02)
                return AgentReport(agent=name, model="inert", findings=[])

            orch.agent_manager.run_agent_async = inert_agent
            exchanges = [
                HttpExchange(url=f"http://{h}/x", method="GET", response_status=200,
                            response_headers={}, response_body="ok")
                for h in ("one.test", "two.test")
            ]

            async def run_both():
                return await asyncio.gather(*[
                    orch.analyze(ex, force_agents=agent_names, bypass_cache=True)
                    for ex in exchanges
                ])

            asyncio.run(run_both())

            self.assertEqual(len(observed_run_ids), 2)
            self.assertNotEqual(observed_run_ids[0], observed_run_ids[1])
            self.assertTrue(all(r for r in observed_run_ids))
            self.assertEqual(telemetry.events(observed_run_ids[0]).get("dispatched"), 1)
            self.assertEqual(telemetry.events(observed_run_ids[1]).get("dispatched"), 1)
        finally:
            store._DB_PATH = orig_db
            cache._cache = orig_cache
            shutil.rmtree(tmp, ignore_errors=True)


class TelemetryEndpointTests(unittest.TestCase):
    def setUp(self):
        telemetry.reset()
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = store._DB_PATH
        store._DB_PATH = Path(self._tmp.name) / "state.db"
        import importlib
        import harness.server as server_module
        importlib.reload(server_module)
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app, base_url="http://localhost")

    def tearDown(self):
        store._DB_PATH = self._orig
        self._tmp.cleanup()
        telemetry.reset()

    def test_telemetry_endpoint_exposes_diagnostics(self):
        telemetry.record_swallowed_exception("universal_header_audit", ValueError())
        resp = self.client.get("/telemetry")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("diagnostics", body)
        diag = body["diagnostics"]
        self.assertIn("swallowed_exceptions", diag)
        self.assertGreaterEqual(diag["swallowed_exceptions"]["total"], 1)
        self.assertIn("coordinator_fail_open", diag)
        self.assertEqual(diag["scope"], "process")

    def test_telemetry_endpoint_accepts_run_id_scope(self):
        telemetry.bind_current_run("scoped-run")
        telemetry.record_swallowed_exception("scoped_site", ValueError())
        telemetry.bind_current_run("")  # back to unscoped for the request itself
        resp = self.client.get("/telemetry", params={"run_id": "scoped-run"})
        self.assertEqual(resp.status_code, 200)
        diag = resp.json()["diagnostics"]
        self.assertEqual(diag["scope"], "run")
        self.assertEqual(diag["run_id"], "scoped-run")
        self.assertIn("scoped_site:ValueError", diag["swallowed_exceptions"]["by_site"])


if __name__ == "__main__":
    unittest.main()
