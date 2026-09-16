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


if __name__ == "__main__":
    unittest.main()
