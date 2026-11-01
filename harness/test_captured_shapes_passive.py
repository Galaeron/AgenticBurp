"""R22 manually supplied captured text shapes; no browser, proxy or target I/O."""
import json
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

from harness import cache, store
from harness import test_pairing_contract as pairing
from harness.test_engagement_atomic_passive import ContextProvider
from harness.test_run_summary_ledger import _build


class CapturedShapeCallerTests(unittest.TestCase):
    def setUp(self):
        pairing.PairingCallerTests.setUp(self)
        previous_cache = cache._cache
        self.addCleanup(setattr, cache, "_cache", previous_cache)
        cache.init_cache(db_path=str(Path(self.tmp.name) / "cache.db"))
        self.provider = ContextProvider()
        self.server.orchestrator = _build(self.provider)
        for target in ["harness.run_context.TargetTransport.execute", "httpx.AsyncClient.request"]:
            guard = patch(target, side_effect=AssertionError("R22 external I/O forbidden"))
            guard.start()
            self.addCleanup(guard.stop)

    def test_captured_text_shapes_reach_passive_analysis_storage_and_exports(self):
        shapes = [
            ("fetch", "PATCH", "application/json", '{"displayName":"ordinary-fetch"}'),
            ("xhr", "POST", "application/x-www-form-urlencoded", "label=ordinary-xhr&locale=en"),
            ("graphql", "POST", "application/json", json.dumps({
                "operationName": "ReadDisplayName", "query": "query ReadDisplayName { viewer { displayName } }",
                "variables": {"locale": "en"}})),
            ("multipart", "POST", "multipart/form-data; boundary=R22Boundary",
                '--R22Boundary\r\nContent-Disposition: form-data; name="label"\r\n\r\nordinary-multipart\r\n'
                '--R22Boundary\r\nContent-Disposition: form-data; name="attachment"; filename="ordinary.txt"\r\n'
                'Content-Type: text/plain\r\n\r\nordinary text\r\n--R22Boundary--\r\n'),
        ]
        pipeline = self.server.orchestrator.analysis_pipeline
        observer = AsyncMock(wraps=pipeline.run_full_analysis)
        with patch.object(pipeline, "run_full_analysis", observer):
            for label, method, content_type, body in shapes:
                with self.subTest(shape=label):
                    self.provider.marker = "ordinary-" + label
                    self.provider.prompts.clear()
                    supplied = {"url": "http://run-summary.test/captured/" + label, "method": method,
                        "request_headers": {"Content-Type": content_type, "Cookie": "session=captured-role-A",
                                            "X-Requested-With": "XMLHttpRequest" if label == "xhr" else "fetch"},
                        "request_body": body, "response_status": 200,
                        "response_headers": {"Content-Type": "application/json"},
                        "response_body": '{"displayName":"ordinary response"}',
                        "capture_id": "synthetic-capture-" + label,
                        "analyst_note": "Captured as role A; analyst supplied label, unverified identity"}
                    response = self.client.post("/analyze", headers=self.auth,
                        json={"engagement_id": "shape-" + label, "exchange": supplied})
                    self.assertEqual(response.status_code, 200)
                    seen = observer.call_args.args[0]
                    self.assertEqual(seen.model_dump(), supplied)
                    self.assertIn(body, " ".join(self.provider.prompts))
                    self.assertIn(content_type, " ".join(self.provider.prompts))
                    records = store.all_host_findings(supplied["url"], engagement_id="shape-" + label)
                    self.assertEqual(records[0]["method"], method)
                    self.assertEqual(records[0]["url"], supplied["url"])
                    self.assertEqual(records[0]["captured_principal_id"], response.json()["captured_principal_id"])
                    finding = response.json()["agent_reports"][0]["findings"][0]
                    evidence = self.client.get(f"/findings/{finding['finding_id']}/evidence", headers=self.auth,
                        params={"engagement_id": "shape-" + label})
                    self.assertEqual(evidence.status_code, 200)
                    self.assertIn("ordinary-" + label, evidence.text)
                    for endpoint in ["/report", "/report/sarif"]:
                        report = self.client.get(endpoint, headers=self.auth,
                            params={"url": supplied["url"], "engagement_id": "shape-" + label})
                        self.assertEqual(report.status_code, 200)
                        if endpoint == "/report":
                            self.assertIn("ordinary-" + label, report.text)
                        else:
                            result = report.json()["runs"][0]["results"][0]
                            self.assertEqual(result["properties"]["requestMethod"], method)
                            self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], supplied["url"])
                            self.assertIn(response.json()["captured_principal_id"], result["properties"]["captured_auth_contexts"])

    def test_defect_control_body_loss_at_ingestion_is_detected(self):
        analyze = self.server.orchestrator.analyze
        seen = []
        async def broken(exchange, *args, **kwargs):
            exchange = exchange.model_copy(update={"request_body": ""})
            seen.append(exchange)
            return await analyze(exchange, *args, **kwargs)
        body = '{"displayName":"ordinary-defect-control"}'
        with patch.object(self.server.orchestrator, "analyze", side_effect=broken):
            response = self.client.post("/analyze", headers=self.auth, json={"engagement_id": "defect-control",
                "exchange": {"url": "http://run-summary.test/captured/fetch", "method": "PATCH",
                             "request_headers": {"Content-Type": "application/json"},
                             "request_body": body, "response_status": 200, "response_body": "ok"}})
        self.assertEqual(response.status_code, 200)
        with self.assertRaises(AssertionError):
            self.assertEqual(seen[0].request_body, body)


if __name__ == "__main__":
    unittest.main()
