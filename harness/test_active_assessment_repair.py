"""Caller controls for the exact-port assessment regression."""
from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx

from harness.assessment_health import assessment_health, review_frontier
from harness.models import HttpExchange, Finding
from harness.run_manifest import RunManifest, _git_state, source_fingerprint
from harness.safety_gate import SafetyGate, SafetyGateConfig, gate_scope


def exchange(url="http://127.0.0.1:3002/api/items", **kw):
    return HttpExchange(url=url, method="GET", response_status=200,
                        response_body=kw.pop("response_body", "items"), **kw)


class PortScopeCallers(unittest.IsolatedAsyncioTestCase):
    async def test_discovery_sends_only_authorized_port(self):
        from harness.api_surface_discovery import SurfaceDiscovery
        sent = []
        async def send(client, request, **kwargs):
            sent.append(str(request.url))
            return httpx.Response(200, text='{"items":[]}', request=request)
        gate = SafetyGate(SafetyGateConfig(active_enabled=True, allowed_hosts=frozenset({"127.0.0.1:3002"})))
        with gate_scope(gate), patch.object(httpx.AsyncClient, "send", send):
            yes = SurfaceDiscovery("http://127.0.0.1:3002", allowed_hosts=["127.0.0.1:3002"])
            no = SurfaceDiscovery("http://127.0.0.1:3001", allowed_hosts=["127.0.0.1:3002"])
            self.assertIsNotNone(await yes._probe("GET", "/api/items"))
            self.assertIsNone(await no._probe("GET", "/api/items"))
        self.assertEqual(sent, ["http://127.0.0.1:3002/api/items"])

    async def test_cors_dispatch_and_offport_negative_control(self):
        from harness.validators.cors_validator import CorsValidator
        sent = []
        async def send(client, request, **kwargs):
            sent.append(str(request.url))
            return httpx.Response(200, text="ok", request=request)
        validator = CorsValidator(allowed_hosts=["127.0.0.1:3002"])
        finding = Finding(vulnerability_class="cors", severity="medium", confidence=.8,
                          summary="test", evidence="", suggested_test="", basis="derived")
        gate = SafetyGate(SafetyGateConfig(active_enabled=True, allowed_hosts=frozenset({"127.0.0.1:3002"})))
        with gate_scope(gate), patch.object(httpx.AsyncClient, "send", send):
            result = await validator.validate(finding, exchange())
            self.assertNotEqual(result.status, "skipped")
            self.assertTrue(sent)
            count = len(sent)
            denied = await validator.validate(finding, exchange("http://127.0.0.1:3001/api/items"))
            self.assertEqual(denied.status, "skipped")
            self.assertEqual(len(sent), count)

    async def test_feature_workflow_scope_at_fetch_boundary(self):
        from harness.feature_workflow import crawl_features
        fetch = AsyncMock(return_value=SimpleNamespace(status_code=200, text="ok", headers={}))
        await crawl_features("http://127.0.0.1:3002", "anonymous", {}, fetch_fn=fetch,
                             allowed_hosts=["127.0.0.1:3002"], max_steps=1)
        self.assertEqual(fetch.await_count, 1)
        await crawl_features("http://127.0.0.1:3001", "anonymous", {}, fetch_fn=fetch,
                             allowed_hosts=["127.0.0.1:3002"], max_steps=1)
        self.assertEqual(fetch.await_count, 1)


class ReviewScheduling(unittest.IsolatedAsyncioTestCase):
    async def test_review_caller_deduplicates_and_gives_other_route_a_turn(self):
        from harness.orchestrator_helpers import review_captured_exchanges
        orch = SimpleNamespace(analyze=AsyncMock(return_value=SimpleNamespace(agent_reports=[])))
        state = SimpleNamespace(record_template=lambda *args: None)
        polling = [exchange(f"http://127.0.0.1:3002/socket.io?t={i}") for i in range(10)]
        seen = set()
        await review_captured_exchanges(orch, state, [polling[0], *polling, exchange()],
                                        max_reviews=2, seen=seen)
        urls = [call.args[0].url for call in orch.analyze.await_args_list]
        self.assertEqual(urls, [polling[0].url, exchange().url])
        await review_captured_exchanges(orch, state, [polling[0], exchange()], seen=seen)
        self.assertEqual(orch.analyze.await_count, 2)

    async def test_distinct_identity_and_response_are_not_collapsed(self):
        observations = [exchange(), exchange(request_headers={"Authorization": "Bearer other"}),
                        exchange(response_body="different")]
        self.assertEqual(len(list(review_frontier(observations))), 3)


class AssessmentEvidence(unittest.TestCase):
    def test_job_caller_exports_only_resolved_current_run_cases(self):
        from harness.test_job_status_passive import DurableJobCallerTests
        from harness import store
        fixture = DurableJobCallerTests('test_completed_job_survives_registry_loss_without_reexecution')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        proof = {}
        async def investigate(*args, **kwargs):
            proof.update(proof_id="p", case={"case_id": "c", "run_id": kwargs['run_context'].run_id},
                         verdict="confirmed")
            return {"findings": [{"confirmed": True, "case_id": "c", "proof_id": "p"},
                                 {"confirmed": True, "case_id": "other", "proof_id": "missing"}]}
        fixture.server.orchestrator.investigate_engagement = investigate
        with patch.object(store, 'proofs_for_case', side_effect=lambda case: [proof] if case == 'c' else []):
            done = fixture.poll(fixture.start(), 'done')
        manifest = json.loads(Path(done['manifest_path']).read_text())
        self.assertEqual(done['result']['confirmed_issues'], 1)
        self.assertEqual(manifest['confirmed_issues'], 1)
        self.assertEqual(manifest['confirmed_issue_refs'][0]['proof_id'], 'p')
        with patch.object(store, 'proofs_for_case', return_value=[]):
            missing = fixture.poll(fixture.start(), 'done')
        self.assertEqual(missing['result']['confirmed_issues'], 0)

    def test_issue_inventory_requires_matching_current_run_proof(self):
        from harness.assessment_health import confirmed_issue_inventory
        finding = {"confirmed": True, "case_id": "case", "proof_id": "proof"}
        proof = {"proof_id": "proof", "case": {"case_id": "case", "run_id": "run"}, "verdict": "confirmed"}
        lookup = lambda case: [proof]
        self.assertEqual(len(confirmed_issue_inventory([finding, finding], "run", lookup)), 1)
        self.assertEqual(confirmed_issue_inventory([finding], "other-run", lookup), [])
        self.assertEqual(confirmed_issue_inventory([dict(finding, proof_id="missing")], "run", lookup), [])

    def test_manifest_marks_incomplete_coverage_even_without_exception(self):
        with tempfile.TemporaryDirectory() as td:
            run = RunManifest.start(run_id="regression", target_identifier="fixture", config={}, output_dir=td)
            run.finish("done", result={"coverage": {"audited": {
                "applicable": 506, "executed": {"numerator": 3}}}})
            data = json.loads(run.path.read_text())
        self.assertEqual(data["completion_status"], "done")
        self.assertEqual(data["assessment"]["status"], "incomplete")
        self.assertTrue(data["degraded"])
        self.assertEqual(assessment_health({"audited": {"applicable": 2, "executed": {"numerator": 2}}})["status"], "complete")

    def test_nested_export_does_not_borrow_parent_git_identity(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent.parent) as td:
            root = Path(td)
            (root / "harness").mkdir()
            source = root / "harness" / "module.py"
            source.write_text("first = 1")
            self.assertEqual(_git_state(root), (None, None))
            first = source_fingerprint(root)
            source.write_text("first = 2")
            self.assertNotEqual(first["sha256"], source_fingerprint(root)["sha256"])

    def test_inferred_detection_still_gets_a_validator_attempt(self):
        from harness.coverage_tracker import CoverageTracker
        from harness.coverage_model import CellStatus
        tracker = CoverageTracker()
        tracker.build({"POST /api/search": {"path": "/api/search", "methods": ("POST",),
                                           "reachable_roles": ["user"]}}, ["user"])
        tracker.matrix.record("user", "POST /api/search", "WSTG-INPV-05",
                              status=CellStatus.DETECTED, reason="model inference")
        calls = []
        async def run(identity, method, path, check):
            calls.append(check.id)
            return SimpleNamespace(status="not_confirmed", summary="control", evidence="", confidence=0, validator="test")
        asyncio.run(tracker.drive_coverage_legs(run, budget=100))
        self.assertIn("WSTG-INPV-05", calls)
        self.assertTrue(tracker.matrix.get("user", "POST /api/search", "WSTG-INPV-05").executed)

    def test_failed_coverage_dispatch_is_visible_and_spends_attempt_budget(self):
        from harness.coverage_tracker import (CoverageTracker, _LEG_CONFIRMATIONS,
                                              _PASSIVE_LEG_CONFIRMATIONS)
        tracker = CoverageTracker()
        tracker.build({"POST /api/search": {"path": "/api/search", "methods": ("POST",)}}, ["user"])
        run = AsyncMock(side_effect=RuntimeError("fixture failure"))
        # Sending legs only: a passive leg spends no attempt budget.
        sending = set(_LEG_CONFIRMATIONS) - _PASSIVE_LEG_CONFIRMATIONS
        self.assertEqual(asyncio.run(tracker.drive_coverage_legs(run, driveable=sending, budget=1)), 1)
        self.assertEqual(run.await_count, 1)
        self.assertEqual(tracker.report()['audited']['not_a_clean_negative']['error'], 1)
        self.assertEqual(tracker.report()['audited']['executed']['numerator'], 0)

    def test_real_pipeline_with_exact_port_and_patched_control(self):
        from harness.test_pipeline_gate import _PipelineRun, _node, _confirmed_idor
        for mode in ("vulnerable", "patched"):
            with self.subTest(mode=mode):
                result, fixture = _PipelineRun(mode, exact_port=True).run()
                self.assertIsNotNone(_node(result, "GET", "/api/notes/{id}"))
                self.assertIn("/openapi.json", fixture.paths())
                self.assertEqual(bool(_confirmed_idor(result)), mode == "vulnerable")


if __name__ == "__main__":
    unittest.main()
